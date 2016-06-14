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

import threading, traceback
from contextlib import contextmanager

from ttproto.core.typecheck	import *
from ttproto.core.data		import *
from ttproto.core		import exceptions, logger, named, snapshot, primitive

__all__ = [
	'Port',
	'BaseMessagePort',
	'RawMessagePort',
	'MessagePort',
	'EventMessageSent',
	'EventMessageReceived',
	'EventMessageMismatch',
]


class Port (named.NamedObject, logger.LoggedObject):
	"""Abstract base class representing a communication port

	Communication ports are used to exchange messages between different
	entities/threads and with the System Under Test.
	"""

	def __init__ (self):
		named.NamedObject.__init__ (self)
		logger.LoggedObject.__init__ (self)

	def __str__ (self):
		return "port:%s" % self.__name__

class BaseMessagePort (Port):
	"""Base class for message-oriented ports


	The BaseMessagePort class handles the forwarding of messages between
	two derived implementations. This process is fully asynchronous. The
	implementation may implement synchronous call on the user side.


            PortImpl_1       BaseMessagePort      PortImpl_2
                 |                  |                  |
         send(…) |                  |                  |
         ------->|  _forward(msg1)  |                  |
                 |----------------->|  enqueue(msg1)   |
         recv(…) |                  |----------------->|
         ------->|                  |                  |
                :|                  |                  |
                :|                  |  _forward(msg2)  |
                :|  enqueue(msg2)   |<-----------------|
                :|<-----------------|                  |
         <------'|                  |                  |
                 |                  |                  |
                 |                  |                  |

	Before exchanging messages, a port shall be connected to another
	MessagePort (using the connect() method).


	NOTE: The current implementation does not allow multiple concurrent
	connections on the same port for the moment.

	"""

	def __init__ (self, endpoint: optional (this_class) = None):
		"""Initialise the port

		If the 'endpoint' parameter is present, this port will be
		immediately connected to this endpoint.
		"""
		Port.__init__ (self)

		self.__endpoint = None
		self.__lock = threading.Lock()
		if endpoint:
			self.connect (endpoint)


	def connect (self, other: this_class):
		"""Connect this port to another port

		The connection is bidirectionnal, and can be broken by any of
		the two ports upon a call to .disconnect().
		"""
		assert isinstance (other, BaseMessagePort)

		if other is self:
			with self.__lock:
				if self.__endpoint:
					raise exceptions.Error("port is already connected")
				self.__endpoint = self

		else:
			la, lb = self.__lock, other.__lock
			if id(la) > id(lb):
				la, lb = lb, la
			with la:
				with lb:
					for p in self, other:
						if p.__endpoint:
							raise exceptions.Error("port is already connected")

					self.__endpoint  = other
					other.__endpoint = self

	def disconnect (self):
		"""Disconnect this port"""
		with self.__lock:
			other = self.__endpoint
			if other is self or other is None:
				self.__endpoint = None
				return

			# we must lock in the right order
			if id(other.__lock) > id(self.__lock):
				with other.__lock:
					self.__endpoint = None
					other.__endpoint = None

		with other.__lock:
			with self.__lock:
				if self.__endpoint == other: # otherwire it means that someone else disconnected it
					self.__endpoint = None
					other.__endpoint = None

	@contextmanager
	def endpoint (self) -> optional (this_class):
		"""Return a context to access the endpoint of this port.

		This contexts the port yields the identity of the endpoint
		connected to this port (or None if not connected).

		When in the context, the port is locked. All other operations
		on the port are blocked until the context is left. Thus the
		endpoint is guaranteed not to change until the context is left.

		Example:
			with my_port.endpoint() as ep:
				print (my_port, "is connected to", ep)

		"""
		with self.__lock:
			yield self.__endpoint


	@typecheck
	def _forward (self, msg: Message) -> bool:
		"""Forward a message to the endpoint of this port

		return False if the port is not connected (else return True)
		"""

		with self.endpoint() as ep:
			if ep is None:
				return False

#			print ("%s->%s: %s" % (self.__name__, ep.__name__, msg))
			ep.enqueue (msg)
			return True

#FIXME: the implementation is not symetrical
class RawMessagePort (BaseMessagePort):

	def __init__ (self, decode_type: is_type = bytes, endpoint = None):
		BaseMessagePort.__init__ (self, endpoint)

		self.__decode_type = get_type (decode_type)


	@typecheck
	def _forward (self, bin_msg: bytes):

		# decode the message
		try:
			msg = Message (bin_msg, self.__decode_type)
		except Exception as e:
			# TODO: log this
			print("Decoding error ->", e)
#			traceback.print_exc()
			msg = Message (bin_msg, primitive.BytesValue)

		return super()._forward (msg)


class MessagePort (snapshot.EventSource, BaseMessagePort):
	"""Message port that can interact with the test

	MessagePort is a message-oriented port that provides a send() function
	to emit a message to the remote port, and a receive(...) event that can
	matched in snapshot blocks.

		Testcase   MessagePort      BaseMessagePort
		    |             |                |
		    |   send(…)   |                |
		    |------------>| _forward(msg1) |
		    |             |--------------->|
		    | receive(…)  |                |
		    |------------>|                |
		    |            :|                |
		    |            :|                |
		    |            :|  enqueue(msg2) |
		    |            :|<---------------|
		    |<-----------'|                |
		    |             |                |
		    |             |                |

	Example:
		link1 = MessagePort()
		link1.connect (some_other_port)

		# synchronous operation (will be blocking)
		link1.send (ping_request_msg)
		link1.receive (ping_request_msg)

		# asynchronous (non-blocking)
		link1.send (ping_request_msg)
		t = Timer()
		t.start (10)
		with alt:
			@link1.receive (ping_request_msg)
			def _():
				set_verdict (pass)

			@link1.receive()
			def _():
				set_verdict (fail)

			@t.timeout()
			def _():
				set_verdict (fail)
	"""

	class ReceiveMatch (snapshot.EventMatch):
		@typecheck
		def __init__ (self, source: snapshot.Event, message: Message, data: optional(is_data)):
			super().__init__(source)
			self.__message = message
			self.__data = store_data (data, none_is_allowed = True)

		def get_message (self):
			return self.__message

		def get_binary (self):
			return self.__message.get_binary()

		def get_value (self):
			return self.__message.get_value()

		def get_data (self):
			return self.__data


	def __init__ (self, endpoint = None):
		snapshot.EventSource.__init__ (self)
		BaseMessagePort.__init__ (self, endpoint)

		self.receive = snapshot.Event (self, "receive")

		self.__queue_in = []
		self.__failed_matches = []

	@typecheck
	def enqueue (self, msg: Message):
		with self.lock:
#			print "%s: enqueue message -> %s" % (self.__name__, msg)
			self.__queue_in.append (msg)

	@typecheck
	def send (self, value: is_value):
		msg = Message (value)
		if not self._forward (msg):
			raise exceptions.PortNotConnected()

		self.log (EventMessageSent, msg, value)

	def evaluate_snapshot (self):
		self.__snapshot_msg = bool (self.__queue_in)

	@typecheck
	def match_receive (self, data: optional (is_data) = None):
		if self.__snapshot_msg:
			assert self.__queue_in

			# TODO: match the template
			msg = self.__queue_in[0]

			mismatch_list = []
			if data is not None and not as_data(data).match(msg.get_value(), mismatch_list):
				if data not in self.__failed_matches:
#					print "%s: mismatch  ->  got: %s, expected: %s" % (self.__name__, msg, data)
					self.__failed_matches.append (data)
					self.log (EventMessageMismatch, msg, data, tuple (mismatch_list))
				return None

#			print("%s: receive message -> %s, expected: %s" % (self.__name__, msg, data))
#			display (msg.get_value())
#			print ("%s:recv:" % self.__name__, msg)

			# TODO: lock the object ??? (is it safe to touch the list now)
			self.__queue_in.pop(0)
			self.__failed_matches[:] = ()

			self.log (EventMessageReceived, msg, data)

			return self.ReceiveMatch (self.receive, msg, data)

		return None

class EventMessageSent (metaclass = logger.LogEventClass):
	fields = (("port", BaseMessagePort),
		  ("message", Message),
		  ("pattern", Data),
		 )
	def summary (self):
		return "%s--> %s" % (self[0].__name__, self[1].summary())

class EventMessageReceived (metaclass = logger.LogEventClass):
	fields = (("port", BaseMessagePort),
		  ("message", Message),
		  ("pattern", Data, True),
		 )
	def summary (self):
		return "%s<-- %s" % (self[0].__name__, self[1].summary())

class EventMessageMismatch (metaclass = logger.LogEventClass):
	fields = (("port", BaseMessagePort),
		  ("message", Message),
		  ("pattern", Data),
		  ("mismatches", tuple)
		 )
	def summary (self):
		return "%s<-- mismatch" % self[0].__name__



