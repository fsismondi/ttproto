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

# FIXME: this is a very dirty script

from ttproto.core import clock, port
from ttproto.core.typecheck import *

from . import local_config
from . import implem
from . import implembR
from . import implemR
from .common import *

import socket, threading
import ttproto.core.lib.inet.all

class UdpServerPort (port.RawMessagePort):

	@typecheck
	def __init__ (self, port_number: int, decode_type: is_type = bytes, endpoint: optional (port.BaseMessagePort) = None):
		super().__init__ (decode_type, endpoint)

		self.__sock = socket.socket (socket.AF_INET6, socket.SOCK_DGRAM)
		self.__sock.bind (("", port_number))

		self.__lock = threading.Lock()
		self.__kill_event = threading.Event()
		self.__peer = None

		self.__thread = threading.Thread (target = self.__thread_func)
		self.__thread.daemon = True
		self.__thread.start()

	def __thread_func (self):
		try:
			while True:
				buff, peer = self.__sock.recvfrom (65535)
				if self.__kill_event.is_set():
					# the port is being killed -> just return silently
					return
				with self.__lock:
					if self.__peer != peer:
						print ("Using new endpoint:", peer)
						self.__peer = peer

				# forward it
				self._forward (buff)
				#TODO: warning if there is no endpoint ?

		except Exception as e:
			print("Error in receiving thread")
			traceback.print_exc()

			#TODO: report the error to the tester

	def enqueue (self, msg: Message):
		assert isinstance (msg.get_binary(), bytes) # supports only byte-aligned data

		with self.__lock:
			peer = self.__peer

		if peer:
			self.__sock.sendto (msg.get_binary(), peer)
		else:	
			print ("%s: warning: ignored (no known peer yet)" % type(self).__name__)
@testcase
def dummy_implem():
	pass


emss_orig = port.EventMessageSent.summary
emrs_orig = port.EventMessageReceived.summary
def emss (self):
	self[1].display()
	return emss_orig (self)
def emrs (self):
	self[1].display()
	return emrs_orig (self)
port.EventMessageSent.summary = emss
port.EventMessageReceived.summary = emrs

with LoggerGroup ([ConsoleLogger(), HTMLLogger()]) as logger:

	logger.log_event (EventTestcaseStarted (dummy_implem))

	imp = implem.SixLowpanImplementation (compression = "-c" in sys.argv)
	imp.get_message_port().add_logger (logger)
	udp = UdpServerPort (13000, Ieee802154, imp.get_message_port())

	imp.daemon = True
	imp.start()
	while True:
		time.sleep(86400)

