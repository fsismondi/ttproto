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

"""Logging module"""

import sys, threading, time

from ttproto.core.typecheck	import *
from ttproto.core.exceptions	import Error
from ttproto.core		import clock

__all__ = [
	'LogEvent',
	'LogEventClass',
	'Logger',
	'ConsoleLogger',
	'LoggerGroup',
	'LoggedObject',
	'EventText',
	'EventStep',
	'log_event',
	'log',
	'step',
]

class LogEvent:
	def __init__ (self, *k):
		if len(k) != len(self.__types):
			raise Error("Expected %d parameters instead of %d" % (len(self.__types), len(k)))

		for i in range (0, len (k)):
			t = self.__types[i]

			if k[i] is None and self.__optional[i]:
				continue

			if not isinstance (k[i], t):
				raise Error("Param id %d is an instance of %s instead of %s" % (i, type(k[i]), t))

		self.__values = k

		self.__timestamp = clock.Clock.get_instance().time()

	def __getattr__ (self, name):
		assert name in self.__names

		return self.__values[self.__names.index (name)]

	@typecheck
	def __getitem__ (self, i: int):
		assert 0 <= i < len (self.__values)

		return self.__values[i]

	def get_timestamp (self):
		return self.__timestamp

	def __str__ (self):
		assert type(self).__name__[0:5] == "Event"

		return "%s %s" % (type(self).__name__[5:], " ".join ([str(v) for v in self.__values]))

	# may be reimplemented
	summary = __str__


class LogEventClass (type):

	def __new__ (cls, name, bases, dct):
		assert bases == ()
		assert "fields" in dct
		assert name[0:5] == "Event"	# just a naming convention
		bases = LogEvent,

		fields = dct.pop("fields")
		assert type (fields) == tuple
		for f in fields:
			assert 2 <= len (f) <= 3
			assert type(f) == tuple
			assert type(f[0]) == str
			if len(f) > 2:
				assert type (f[2]) == bool
			# TODO: some assertion on f[1]'s type ?

		dct["_LogEvent__names"], dct["_LogEvent__types"] = zip (*fields)
		dct["_LogEvent__optional"] = tuple (False if len(f) < 3 else f[2] for f in fields)

		return type.__new__ (cls, name, bases, dct)


#TODO: add timestamps
class Logger:
	def log_event (self, event):
		pass

	@classmethod
	@typecheck
	def set_default (cls, logger: this_class):
		cls.__default_logger = logger

	@classmethod
	def get_default (cls):
		return cls.__default_logger

	def __enter__ (self):
		return self

	def __exit__ (self, a, b, c):
		pass


class ConsoleLogger (Logger):

	__linebreak = set (("EventTestcaseStarted", "EventTestcaseTerminated", "EventSessionStarted", "EventSessionTerminated", "EventSessionAborted"))

	def __init__ (self, file = sys.stdout, summary = True):
		self.__lock = threading.Lock()
		self.__file = file
		self.__summary = summary
		self.__origin = None

	@typecheck
	def log_event (self, event: LogEvent):
		with self.__lock:
			if self.__origin is None:
				self.__origin = event.get_timestamp() // 1000 * 1000
				print ("clock origin: %d (%s)" % (self.__origin, time.ctime (self.__origin)))
			br = "\n" if type(event).__name__ in self.__linebreak else ""
			print ("%s[%03.4f] %s\n%s" % (br, (event.get_timestamp() - self.__origin), event.summary() if self.__summary else event, br), file = self.__file, end="")

			if type(event).__name__ == "EventTestcaseRuntimeError":
				for line in event.traceback.split("\n"):
					print ("             " + line, file = self.__file)


Logger.set_default (ConsoleLogger())


class LoggerGroup (Logger):
	@typecheck
	def __init__ (self, loggers: list_of (Logger) = []):
		self.__loggers = list (loggers)

	@typecheck
	def add_logger (self, logger: Logger):
		self.__loggers.push (logger)

	def log_event (self, event):
		for l in self.__loggers:
			l.log_event (event)

	def __enter__ (self):
		for l in self.__loggers:
			l.__enter__()
		return self

	def __exit__ (self, a, b, c):
		for l in self.__loggers:
			l.__exit__(a, b, c)

class LoggedObject:

	def __init__ (self):
		self.__loggers = []

	@typecheck
	def add_logger (self, logger: Logger):
		self.__loggers.append (logger)

	def log (self, event_type, *k):
		assert issubclass (event_type, LogEvent)

		ev = event_type (self, *k)

		# current thread's logger
		log_event(ev) # FIXME: will raise an error if the thread is not derived from snapshot.Thread

		# object-specific loggers
		for l in self.__loggers:
			l.log_event (ev)

class EventText (metaclass = LogEventClass):
	fields = (("txt", str),)
	def summary (self):
		return self[0]

class EventStep (metaclass = LogEventClass):
	fields = (("name", str),
		  ("description", str))
	def summary (self):
		return "Step %s%s%s" % (
				self[0],
				" - " if self[1] else "",
				self[1]
		)

@typecheck
def log_event (event: LogEvent):
	threading.current_thread().log_event(event) # FIXME: will raise an error if the thread is not derived from snapshot.Thread

def log (*k):
	log_event (EventText (" ".join(str (v) for v in k)))

def step (name, *k):
	log_event (EventStep (str (name), " ".join(str (v) for v in k)))

