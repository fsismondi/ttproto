#!/usr/bin/env python3
#
#   (c) 2012  Universite de Rennes 1
#
# Contact address: <t3devkit@irisa.fr>
#
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.
# -*- coding: utf-8 -*-

"""This module implement the snapshot semantics of ttproto

"""

import numbers, threading, types

from	ttproto.core.typecheck	import *
from	ttproto.core		import clock, exceptions, logger, named

from	contextlib	import contextmanager

# TODO: split into several modules
_all__ = [
	'SnapshotBlock',
	'AltBlock',
	'SnapshotManager',
	'repeat',
	'SnapshotContext',
	'alt',
	'EventSource',
	'Event',
	'EventMatch',
	'Timer',
	'EventTimerStarted',
	'EventTimerStopped',
	'EventTimerTimeout',
	'Altstep',
	'AltstepBlock',
	'altstep',
]


# TODO: document subtilities
#
#	@altstep
#	def match_timeout (*timer_list):
#
#		for timer in timer_list:
#			@timer.timeout
#			def _():
#				print "timer timeout !", timer
#				repeat()
#   -> invalid use of free variables in the handler function
#      here, 'timer' will always refer to the last timer in the list
#      because both events branchs are instantiated in the same frame
#

class SnapshotBlock:
	"""A snapshot block holds a list of branches that can be followed


	"""
	#FIXME: Block may not be the most adequate name

	@typecheck
	def __init__ (self, name: optional (str) = None):
		self.branch_list = []
		self.__parent = None
		self.__name = name

	@typecheck
	def stack (self) -> iterable:
		'''returns an iterator on the block stack'''

		while self:
			yield self
			self = self.__parent

	@typecheck
	def push (self, block: this_class) -> this_class:
		'''returnes the new base of the stack'''

		assert block.__parent is None
		block.__parent = self
		return block

	@typecheck
	def pop (self) -> this_class:
		'''returnes the new base of the stack'''
		result = self.__parent
		self.__parent = None
		return result

	@typecheck
	def get_sources (self) -> iterable:
		for g in self.branch_list:
			for s in g.event.get_sources():
				yield s
		if self.__parent:
			for s in self.__parent.get_sources():
				yield s

	def match (self)  -> "optional (EventMatch)":
		raise NotImplementedError()


class AltBlock (SnapshotBlock):

	def match (self)  -> "optional (EventMatch)":

#		print "enter alt match"
		for block in self.stack():
#			print "  block", block
			if isinstance (block, AltBlock):
				# evaluate the conditions
				for g in block.branch_list:
#					print "  try", g
					em = g.match()
					if em:
						# matched the event!
#						print "leave alt match"
						em.set_branch (g)
						return em
#		print "leave alt match"
		return None

#TODO: the 'editable' concept is not very clear -> document clearly when a block is no longer editable and what are the implications
class SnapshotManager:
	"""SnapshotManager is the main class controling the snapshot semantics.

	There is one SnapshotManager object associated to each thread
	performing snapshot operations. These instances are created
	automatically the first time the manager object is needed by the
	thread.

	"""

	__thread_local = threading.local()


	# Key: 	 SnapshotManager object
	# Value: True if the thread is running
	#	 False if the thread is awaiting external events
	__tracked_managers = {}
	__tracked_lock = threading.Lock()


	class Repeat (BaseException):
		"""Repeat Exception

		This exception notifies the snapshot manager that the current
		snapshot block should be reevaluated again.

		It can can be raised by:
		- an Event (in its test function: match_xxxxxxx())
		- a branch handler executed upon an event is match
		- a snapshot block being matched
		"""
		pass

	class Sources:
		"""A class for listing the event sources that are grabbed by a snapshot manager.

		This class maintains a set() containing all the event sources
		reverenced in the active branchs of a snapshot manager.

		When a source is added to the collection, it is grabbed by this
		manager (other snapshot manager won't be able tu use it).
		Events occuring within this source will be reported to this
		manager.

		When a source is removed from the collection, the grab is removed.
		"""

		def __init__ (self, manager: "SnapshotManager"):
			self.__set = set()
			self.__manager = manager

		def __iter__ (self):
			return self.__set.__iter__()

		@typecheck
		def update (self, block: SnapshotBlock):
			new_set = set()
			for s in block.get_sources():
				new_set.add (s)

			# grab the new sources
			for s in new_set.difference (self.__set):
				s.set_listener (self.__manager)

			# ungrab the older sources
			for s in self.__set.difference (new_set):
				s.clear_listener (self.__manager)

			self.__set = new_set


		def add (self, source: "EventSource"):
			if source in self.__set:
				return

			self.__set.add (source)
			source.set_listener (self.__manager)

		def clear (self):
			for s in self.__set:
				s.clear_listener (self.__manager)

			self.__set.clear()

	class Branch:
		"""A branch is a path that can be followed in a snapshot block

		A branch is associated to a condition: an Event to be observed
		(possibly with some parameters).

		Optionally the branch can have a handler function, which is
		executed when branch is successfully entered (which implies
		that condition is fulfilled).

		The order in which Branch objects are evaluated is out of the
		scope of this class. It depends on the snapshot block in which
		the are created.

		Branch object are usually never created with an explicit
		instantiation. These objects are created when calling an Event
		object.

		Example:
			with alt:
				# creation of a branch (w/o handler)
				timer.timeout()

				# creation of a branch (w/ handler)
				port.receive(some_message)
				def _():
					print ("message received !)


		"""
		def __init__ (self, event: "Event", *k, **kw):
			self.event = event
			self.k = k
			self.kw = kw
			self.handler = None

		def match (self) -> "optional (EventMatch)":
			return self.event.match (*self.k, **self.kw)

		@typecheck
		def attach_handler (self, func: callable):
			assert self.handler is None
			self.handler = func

	class Thread (threading.Thread):
		"""A thread tied to the local snapshot manager.

		 - its interruption function will notify the local snapshot manager
		 - its status will be tracked by the snapshot manager class
		"""

		__lock = threading.Lock()

		def __init__ (self, *k, **kw):
			threading.Thread.__init__ (self, *k, **kw)

			self.__logger = logger.Logger.get_default()

		def start (self):
			if not self.run is self.__run:
				self.__target = self.run
				self.run = self.__run

			self.__lock.acquire()
			threading.Thread.start (self)

		def __run (self, *k, **kw):
			sm = SnapshotManager()

			self.interrupt = sm.interrupt
			self.__lock.release() # FIXME: releasing in a different thread may not be portable

			with sm.track():
				self.__target(*k, **kw)

		def log_event (self, event: logger.LogEvent):
			self.__logger.log_event (event)

	def __new__ (cls):

		if not hasattr (cls.__thread_local, "manager"):
			self = super (SnapshotManager, cls).__new__(cls)

			self.__thread = threading.currentThread()

			self.__sources = SnapshotManager.Sources (self)
			self.__block = None
			self.__interrupted = False

			self.__lock = threading.Lock()
			self.__cond_update = threading.Condition (self.__lock)

			SnapshotManager.__thread_local.manager = self
		return	SnapshotManager.__thread_local.manager

	def __repr__ (self):
		return "<SnapshotManager %s>" % repr (self.__thread)

	def reset (self):
		self.__sources.clear()
		self.__block = None
		self.__interrupted = False

	def interrupt (self):
		with self.__lock:
			self.__interrupted = True
			self.__cond_update.notify()

			self.__track_wake_up()

	@contextmanager
	def track (self):
		with self.__tracked_lock:
			assert self not in self.__tracked_managers
			self.__tracked_managers[self] = True
		try:
			yield
		finally:
			with self.__tracked_lock:
				assert self in self.__tracked_managers
				del self.__tracked_managers[self]

	def __track_wake_up (self):
		with self.__tracked_lock:
			if self in self.__tracked_managers:
				self.__tracked_managers[self] = True

	def __track_wait (self):
		with self.__tracked_lock:
			if self not in self.__tracked_managers:
				return

			self.__tracked_managers[self] = False

			if any (self.__tracked_managers.values()):
				return

		# All threads are waiting for external events
		# -> notify the clock
		clock.Clock.get_instance().all_threads_blocked()

	@classmethod
	def all_tracked_threads_blocked (cls):
		with cls.__tracked_lock:
			return not any (cls.__tracked_managers.values())

	def run (self) -> "optional(EventMatch)":

		self.__obsolete = True # FIXME: not very clean to touch it when not locked

		try:
			while True:
				with self.__lock:
					if self.__interrupted:
						raise exceptions.UserInterrupt()

					# update the list of sources
					self.__sources.update (self.__block)

					# possibly wait for new events
					if not self.__obsolete:

						self.__track_wait()

#						print "wait"
						self.__cond_update.wait()

						if self.__interrupted:
							raise exceptions.UserInterrupt()

					# make the snapshot
					for s in self.__sources:
						s.evaluate_snapshot()

					self.__obsolete = False

				try:
					event_match = self.__block.match()
					if event_match:
						# force the reevaluation of the snapshot (we may have received 2 events at once)
						self.__obsolete = True # FIXME: not very clean to touch it when not locked

						event_match.call_handler()
						return event_match
				except SnapshotManager.Repeat:
#					print "repeat"
					pass
		finally:
			# clear the source list
			self.__sources.clear()
			pass

	def push_event (self, event: "Event", *k, **kw) -> callable:
		# create a branch to handle that event
		branch = SnapshotManager.Branch (event, *k, **kw)

		if self.__block and self.__block.__editable:
			# we are in an editable block

			# append it to the list of the current block
			self.__block.branch_list.append (branch)

			# return a function to allow attaching a handler to the
			# branch statement
			return branch.attach_handler
		else:
			# the block is not editable
			# -> assume that we have to process the instruction now

			# alt block is the default
			self.push_block (AltBlock())
			try:
				self.__block.branch_list.append (branch)

				event_match = self.run()
				if event_match and event_match.get_branch() == branch:
					def result (func):
						func()
				else:
					def result (func):
						pass
				return result
			finally:
				self.pop_block()

	def lock (self):
		self.__lock.acquire()

	def unlock (self):
		self.__obsolete = True
		self.__cond_update.notify()
		self.__track_wake_up()
		self.__lock.release()

	@typecheck
	def push_block (self, block: SnapshotBlock, editable: bool = False, fail_if_editing: bool = True):

		if fail_if_editing and self.__block:
			assert not self.__block.__editable # TODO: document this error (needed to avoid breaking things with an altstep definition inside another block TODO: check that this assertion is correct


		if self.__block:
			self.__block = self.__block.push (block)
		else:
			self.__block = block

		self.__block.__editable = editable

	@typecheck
	def pop_block (self, keep_editable: bool = False):
		assert self.__block

		self.__block = self.__block.pop()

		if self.__block and not keep_editable:
			self.__block.__editable = False
def repeat():
	raise SnapshotManager.Repeat()

class SnapshotContext:
	def __init__ (self, cls):
		self.__cls = cls

	def __enter__ (self):
		SnapshotManager().push_block (self.__cls(), editable = True)

	def __exit__ (self, exc_type, exc_value, traceback):
		sm = SnapshotManager()
		try:
			if not exc_type:
				sm.run()
		finally:
			sm.pop_block()

alt = SnapshotContext(AltBlock)


class EventSource:
	class Lock:
		def __init__ (self, source):
			self.__source = source
		def __enter__ (self):
			self.__source._lock()
		def __exit__ (self, a, b, c):
			self.__source._unlock()

	def __init__ (self):
		self.__listener	= None
		self.__lock	= threading.Lock()
		self.lock	= EventSource.Lock (self)

	@typecheck
	def set_listener (self, listener: SnapshotManager):
		with self.__lock:
			assert self.__listener is None  # TODO: report an error if not

			self.__listener = listener

	@typecheck
	def clear_listener (self, listener: SnapshotManager):
		with self.__lock:
			assert self.__listener == listener

			self.__listener = None

	def _lock (self):
		self.__lock.acquire()
		if self.__listener:
			self.__listener.lock()

	def _unlock (self):
		if self.__listener:
			self.__listener.unlock()
		self.__lock.release()

class Event:
	@typecheck
	def __init__ (self, source: EventSource, name: str):
		self.__source = source

		# TODO: check that the match function exists
		self.__match_func = getattr (source, "match_" + name)

	@typecheck
	def __call__ (self, *k, **kw) -> either (nothing, callable):
		if kw or len(k) != 1 or type (k[0]) != types.FunctionType:
			# event called with parameters
			return SnapshotManager().push_event (self, *k, **kw)
		else:
			# event called without any parameter
			# (just used to tag the function)
			# FIXME: might not be a good idea (because this function would not be called if it is not a tag)
			return SnapshotManager().push_event (self) (*k, **kw)

	@typecheck
	def get_sources (self) -> iterable:
		yield self.__source

	@typecheck
	def get_source (self) -> EventSource:
		return self.__source

	def match (self, *k, **kw) -> "optional (EventMatch)":
		result = self.__match_func (*k, **kw)
		assert result is None or isinstance (result, EventMatch)
		return result

class EventMatch:
	def __init__ (self, event):
		self.__event = event
		self.__branch = None

	@typecheck
	def set_branch (self, branch: SnapshotManager.Branch):
		self.__branch = branch

	@typecheck
	def get_branch (self) -> optional (SnapshotManager.Branch):
		return self.__branch

	def get_event (self):
		return self.__event

	def get_source (self):
		return self.__event.get_source()

	def call_handler (self):
		#TODO: support any callable object
		#TODO: support *k and **kw

		assert self.__branch is not None  # FIXME: not sure about this one

		func = self.__branch.handler

		if func is None:
			# no handler set
			# -> just return
			return None

		self.__branch = None # reset the branch (to ensure that the handler is not called twice)

		nb = func.__code__.co_argcount
		if not nb:
			return func()
		else:
			params = []
			for name in func.__code__.co_varnames[0:nb]:
				assert hasattr (self, "get_" + name)  # unknown parameter in event callback
				params.append (getattr (self, "get_" + name) ())

			return func (*params)


class Timer (EventSource, logger.LoggedObject, named.NamedObject):

	def __init__ (self, duration = None):
		EventSource.__init__ (self)
		logger.LoggedObject.__init__ (self)
		named.NamedObject.__init__ (self)

		self.timeout = Event (self, "timeout")

		self.__clock = None
		self.__running = False

		if duration is not None:
			self.start (duration)

	def __str__ (self):
		return "timer:%s" % self.__name__

	def start (self, duration):
		with self.lock:
			# cancel the previous timer if any
			if self.__clock:
				self.__clock.unschedule_events (self.__callback)

			# start a new timer
			self.__running = True
			self.__clock   = clock.Clock.get_instance()

			self.__clock.schedule_event_relative (duration, self.__callback)

		self.log (EventTimerStarted, duration)


	def stop (self):
		with self.lock:
			if self.__clock:
				self.__clock.unschedule_events (self.__callback)
				self.__clock = None
				self.__running = False

		self.log (EventTimerStopped)

	def evaluate_snapshot (self):
		self.__snapshot_running = self.__running

	@typecheck
	def match_timeout (self) -> optional (EventMatch):
		if self.__snapshot_running or not self.__clock:
			return None

		self.__clock = None

		self.log (EventTimerTimeout)
		return EventMatch (self.timeout)

	def __callback (self):
		with self.lock:
#			print "timeout callback", self
			self.__running = False


class EventTimerStarted (metaclass = logger.LogEventClass):
	fields = (("timer", Timer),
		  ("duration", numbers.Number),
		 )

	def summary (self):
		return "timer %s started: %s seconds" % (self[0].__name__, self[1])

class EventTimerStopped (metaclass = logger.LogEventClass):
	fields = (("timer", Timer),)

	def summary (self):
		return "timer %s stopped" % self[0].__name__

class EventTimerTimeout (metaclass = logger.LogEventClass):
	fields = (("timer", Timer),)

	def summary (self):
		return "timer %s timeout" % self[0].__name__

# TODO: write a generic class that handles the complex parts of Altstep so that it can be reused for other purposes
class Altstep:
	@typecheck
	def __init__ (self, func: types.FunctionType):
		self.__func = func

	@typecheck
	def __call__ (self, *k, **kw) -> either (nothing, callable):
		block = AltstepBlock (self.__func, *k, **kw)

		# register the event in the snapshot manager
		return block.event()

	#TODO: implement AltstepBlock.deactivate()
	def activate (self, *k, **kw) -> "AltstepBlock":
		block = AltstepBlock (self.__func, *k, **kw)

		SnapshotManager().push_block(block)

		return block

	@staticmethod
	@typecheck
	def create (func: types.FunctionType):
		# create the altstep event source
		return Altstep (func)


class AltstepBlock (EventSource, AltBlock):

	@typecheck
	def __init__ (self, func: types.FunctionType, *k, **kw):
		EventSource.__init__(self)
		AltBlock.__init__(self, func.__name__)

		# Populate the altstep with events
		sm = SnapshotManager()
		sm.push_block (self, editable = True, fail_if_editing = False)
		try:
#			print " running code", func, k, kw
			func (*k, **kw)
		finally:
			sm.pop_block (keep_editable = True)

		self.event = Event (self, "altstep")
		self.event.get_sources = self.get_sources

	@typecheck
	def match_altstep (self) -> optional (EventMatch):
		event_match = self.match()

		if event_match:
			# run it (FIXME: might not be the right place to do this)
			event_match.call_handler()

		return event_match

altstep = Altstep.create

