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

import atexit, threading, tempfile, os, signal, socket, time, weakref, traceback

from ttproto.core.typecheck	import *
from ttproto.core.data		import *
from ttproto.core		import exceptions, port

class SocatMessagePort (port.RawMessagePort):

	@typecheck
	def __init__ (self, socat_endpoint: str, decode_type: is_type = bytes, endpoint: optional (port.BaseMessagePort) = None):
		port.RawMessagePort.__init__ (self, decode_type, endpoint)

		tmpdir = tempfile.mkdtemp()
		self.__sockname = os.path.join (tmpdir, "sock_my")
		self.__sockname_socat = os.path.join (tmpdir, "sock_socat")
		self.__kill_event = threading.Event()

		# create the socket
		self.__sock = socket.socket (socket.AF_UNIX, socket.SOCK_DGRAM)
		self.__sock.bind (self.__sockname)

		# launch socat
		self.__pid = os.fork()
		if not self.__pid:
			# child
			os.execl ("/usr/bin/socat", "socat",
					socat_endpoint,
					"UNIX-CONNECT:%s,bind=%s,type=%d" % (self.__sockname, self.__sockname_socat, socket.SOCK_DGRAM))
		retry = 10
		while True:
			try:
				time.sleep(0.1)
				self.__sock.connect (self.__sockname_socat)
				break
			except socket.error as e:
				retry -= 1
				if retry == 0:
					raise e

		# launch a listening thread
		self.__thread = threading.Thread (target = self.__thread_func)
		# this is a daemon thread (will not block at exit)
		self.__thread.daemon = True
		self.__thread.start()

		# register an exit handler to free the resources when leaving
		atexit.register (self.kill)

	@typecheck
	def enqueue (self, msg: Message):
		assert isinstance (msg.get_binary(), bytes) # supports only byte-aligned data
		try:
			self.__sock.send (msg.get_binary())
		except Exception as e:
			if not self.__kill_event.is_set():
				print("Cannot send the message")
				traceback.print_exc()
				#FIXME: should have an error handler that reports an error verdict

	def __thread_func (self):
		try:
			while True:
				buff = self.__sock.recv (65535)
				if len (buff) == 0 and self.__kill_event.is_set():
					# the port is being killed -> just return silently
					return

				# forward it
				self._forward (buff)
				#TODO: warning if there is no endpoint ?

		except Exception as e:
			print("Error in receiving thread")
			traceback.print_exc()

			#TODO: report the error to the tester

	def kill (self):
		# set the kill event (to notify other threads)
		self.__kill_event.set()

		# close the socket (this will terminate the listening thread)
		self.__sock.shutdown(socket.SHUT_RDWR)

		# stop the socat process
		os.kill (self.__pid, signal.SIGTERM)
		os.waitpid (self.__pid, 0)

		# remove the tmp files
		os.unlink (self.__sockname)
		os.unlink (self.__sockname_socat)
		os.rmdir (os.path.dirname (self.__sockname))

		# unregister our exit handler
		atexit.unregister (self.kill)

