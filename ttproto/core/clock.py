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

import numbers, threading, time, types
from	ttproto.core.typecheck	import *

from ttproto.core import exceptions

# TODO: split into several modules
_all__ = [
	'Clock',
	'EventQueueClock',
	'SystemClock',
	'SimulatedClock',
]

class Clock:
	# TODO: maybe support multiple clocks in the same process ?
	__instance = None
	__lock = threading.Lock()

	@staticmethod
	def get_instance():
		return Clock.__instance

	@staticmethod
	@typecheck
	def set_instance (clock: this_class):
		with Clock.__lock:
			if Clock.__instance:
				# FIXME: what to do with the scheduled events ?
				#	 maybe it would be better to raise an exception here
				Clock.__instance.kill()

			Clock.__instance = clock

	def unschedule_events (self, callback: types.MethodType):
		raise exceptions.NotImplemented()

	@typecheck
	def schedule_event_absolute (self, time: numbers.Number, callback: callable):
		raise exceptions.NotImplemented()

	@typecheck
	def schedule_event_relative (self, time: numbers.Number, callback: callable):
		raise exceptions.NotImplemented()

	def reset (self):
		raise exceptions.NotImplemented()

	def kill (self):
		pass

	def time (self):
		raise exceptions.NotImplemented()

	def all_threads_blocked (self):
		"""Called by SnapshotManager when all threads are waiting for an external event"""
		pass

def _Condition (lock):
	"""Wrapper for threading._Condition() implementing the result value in
	Condition.wait() (as implemented in Python 3.2)

	(to be removed once we upgrade to python 3.2)

	NOTE: this wrapper won't work correctly if multiple threads are calling
	wait() concurrently

	NOTE: this wrapper won't work with notify_all()
	"""

	cond = threading.Condition (lock)

	super_notify	= cond.notify
	super_wait	= cond.wait

	notify_received	= False

	def notify():
		nonlocal notify_received

		notify_received = True
		super_notify()

	def wait (timeout = None):
		nonlocal notify_received

		notify_received = False
		super_wait (timeout)
		return notify_received

	cond.notify	= notify
	cond.wait	= wait

	return cond


class EventQueueClock (Clock):
	"""An event is stored as a tuple (timestamp, time) and are ordered chronologically in the queue"""

	def __init__ (self):
		Clock.__init__ (self)

		self.__queue = []
		self._lock = threading.Lock()
		self._cond = _Condition(self._lock)

	@typecheck
	def schedule_event_relative (self, time: numbers.Number, callback: callable):
		with self._lock:
			self.__new_event (self._time() + time, callback)

	@typecheck
	def schedule_event_absolute (self, time: numbers.Number, callback: callable):
		with self._lock:
			self.__new_event (time, callback)

	def unschedule_events (self, callback):
		with self._lock:
			q = self.__queue
			i = len (q) - 1
			while i>=0:
				if q[i][1] == callback:
					q.pop(i)
				i-=1

			self._cond.notify()

	def reset (self):
		with self._lock:
			self.__queue[:] = ()

			self._cond.notify()

	def __new_event (self, time, callback):
		assert self._lock.locked()

		diff = self._time() - time
		if diff > 0:
			print ("WARNING: setting an event in the past (%e seconds in the past)" % diff)
			#TODO: allow a jitter margin, raise an exception if over the threshold

		for i in range (0, len (self.__queue)):
			if time < self.__queue[i][0]:
				self.__queue.insert (i, (time, callback))
				break
		else:
			self.__queue.append ((time, callback))

		self._cond.notify()

	@typecheck
	def _get_first_event (self) -> optional (tuple):
		assert self._lock.locked()

		return self.__queue[0] if len (self.__queue) else None

	def _shift (self):
		assert self._lock.locked()
		assert len (self.__queue)

		self.__queue.pop(0)

	def time (self):
		with self._lock:
			return self._time()

	def _time (self):
		assert self._lock.locked()

		raise exceptions.NotImplemented()


class SystemClock (EventQueueClock):
	def __init__ (self):
		EventQueueClock.__init__ (self)
		self.__thread = threading.Thread (target = self.__thread_func)
		self.__thread.daemon = True
		self.__thread.start()

	def kill (self):
		with self._lock:
			assert self.__thread

			thread = self.__thread
			self.__thread = None

			self._cond.notify()

		thread.join()

	def _time (self):
		assert self._lock.locked()

		return time.time()


	def __thread_func (self):

		while True:
			with self._lock:
				if self.__thread != threading.current_thread():
					return

				ev = self._get_first_event()

				if ev:
					remaining_time = ev[0] - self._time()
					if remaining_time > 0:
						self._cond.wait (remaining_time)
						continue
				else:
					self._cond.wait()
					continue

				self._shift()

			# report the event
			ev[1]()

class SimulatedClock (EventQueueClock):
	def __init__ (self):
		EventQueueClock.__init__ (self)

		self.__current_time = None

		self.__killed = False

		self.__thread = threading.Thread (target = self.__thread_func)
		self.__thread.daemon = True
		self.__thread.start()

	def kill (self):
		with self._lock:
			self.__killed = True
			self._cond.notify()

		self.__thread.join()

	def _time (self):
		assert self._lock.locked()

		if self.__current_time is None:
			return 0 # FIXME: should have a better way to do it
			raise exceptions.Error ("Simulated clock not yet started")
		else:
			return self.__current_time

	def reset (self):
		with self._lock:
			self.__current_time = None
		super().reset()

	def start (self):
		with self._lock:
			ev = self._get_first_event()

			self.__current_time = ev[0] if ev else 0

	def __thread_func (self):
		from ttproto.core import snapshot

		with self._lock:
			while True:
				self._cond.wait()

				if self.__killed:
					return

				if self.__current_time is None:
					# clock not yet started
					# -> wait for the signal
					continue

				# clock is running

				while True:
					ev = self._get_first_event()
					if not ev:
						# no events in the queue
						if snapshot.SnapshotManager.all_tracked_threads_blocked():
							# TODO: stop the execution
							print ("Error: deadlock detected")
						break

					if (ev[0] <= self.__current_time):
						# the event is due
						# -> remove it from the list and report it
						self._shift()

						try:
							self._lock.release()
							ev[1]()
						finally:
							self._lock.acquire()

						if self.__current_time is None:
							break

					elif snapshot.SnapshotManager.all_tracked_threads_blocked():
						# all threads are in waiting state
						if ev:
							if ev[0] > self.__current_time:
								# -> advance the clock to the time of the next event
								self.__current_time = ev[0]
					else:
						# other threads are running
						# -> wait
						break




	def all_threads_blocked (self):
		with self._lock:
			self._cond.notify()


Clock.set_instance (SystemClock())


#raise "Je pense que j'ai un gros deadlock entre SimulatedClock et SnapshotManager"
