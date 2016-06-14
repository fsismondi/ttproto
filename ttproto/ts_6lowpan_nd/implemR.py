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
import numbers, threading, traceback
from .common import *

from ttproto.core import	clock, snapshot, exceptions

from ttproto.core.templates import Superset #FIXME: why we need it ?!

__all__ = [
	"SixLowpanImplementation",
]

class Scheduler (snapshot.EventSource):
	class Event:
		@typecheck
		def __init__ (self, process, name: optional(str)):
			self.process = process
			self.name = name


	def __init__ (self, clk: optional (clock.Clock) = None):
		super().__init__()

		self.__clock = clk if clk is not None else clock.Clock.get_instance()
		self.event = snapshot.Event (self, "event")

		self.__events = []
		self.__expired_events = []
		
	
	def reset (self):
		with self.lock:
			for e in self.__events:
				self.__clock.unschedule_events (e)
			self.__events  = []
			self.__expired_events = []
	
	@typecheck
	def __find_event (self, process, name: str):
		for e in self.__events:
			if e.process == process and e.name == name:
				return e
	
	@typecheck
	def __unschedule_event (self, process, name: str):
		ev = self.__find_event (process, name)
		if ev is not None:
			self.__clock.unschedule_events (ev)
			self.__events.remove (ev)
			try:
				self.__expired_events.remove (ev)
			except ValueError:
				pass
	
	@typecheck
	def __prepare_schedule_event (self, process, name: optional(str) = None):
		if name is not None:
			self.__unschedule_event (process, name)

		ev = self.Event (process, name)
		self.__events.append (ev)
		def callback():
			with self.lock:
				self.__expired_events.append (ev)
			
		return callback
	
	@typecheck
	def schedule_event_relative (self, time: numbers.Number, process, name: optional(str) = None):
		with self.lock:
			self.__clock.schedule_event_relative (time, self.__prepare_schedule_event (process, name))

	@typecheck
	def schedule_event_absolute (self, time: numbers.Number, process, name: optional(str) = None):
		with self.lock:
			self.__clock.schedule_event_absolute (time, self.__prepare_schedule_event (process, name))
	
	def evaluate_snapshot(self):
		self.__snapshot_expired_events = len (self.__expired_events)

	def time (self):
		return self.__clock.time()
	
	class __EventMatch (snapshot.EventMatch):
		def __init__ (self, snapshot_event, ev):
			super().__init__ (snapshot_event)
			self.__event = ev

		def get_ev (self):
			return self.__event

	def match_event (self):

		while self.__snapshot_expired_events:

			self.__snapshot_expired_events -= 1
			ev = self.__expired_events.pop(0)
			try:
				self.__events.remove (ev)
			except ValueError:
				#print ("WARNING: FIXME: unscheduled event still present")
				pass
			else:
				return self.__EventMatch (self.event, ev)
	
		return None


class SixLowpanImplementation (snapshot.SnapshotManager.Thread):

	class ConfigClass:
		pass
	config = ConfigClass()
	config.debug = 1
	config.eui64 = "0200000001020304"
	config.routeraddr = ""

	#delay we use when we schedule a RS
	config.DelayRS = 0.1

	#delay we use when we schedule a NS
	config.DelayNS = 0.1

	# time to refresh before a router expire
	config.routerRefreshTime = 6
	# time to refresh before an address expire
	config.AddressRefreshTime = 6


	#FIXME # list of prefix
	PRFX1 = "2001:0db8:1:1::"
	PRFX2 = "fdea:1ffc:f851::"
	list_of_prefix = [PRFX1,PRFX2]


	class Process:
	
		def __init__ (self, implem, func, *k, **kw):
			"""Initialise the new process
			
			- implem	the implementation (python object) hosting this process 
			- function	generator function implementing the behaviour of this process

			"""
			self.__generator  = func (self, *k, **kw)
			self.__scheduler  = implem.get_scheduler()
			next (self.__generator)

		def send (self, msg):
			"""Report an event (message) to the process"""

			return self.__generator.send (msg)

		@typecheck
		def schedule_event_relative (self, time: numbers.Number, name: optional(str) = None):
			"""Schedule an event in the future.

			- time		the time at which the event is to be reported
			- name		name of the event (optional)

			The time is given in seconds starting from now.

			The name is optional. If there is already an existing
			event with the same name for the same process, then
			this existing event is overwritten by the new one.		
			"""
			self.__scheduler.schedule_event_relative (time, self, name)

		@typecheck
		def schedule_event_absolute (self, time: numbers.Number, name: optional(str) = None):
			"""Schedule an event in the future.

			- time		the time at which the event is to be reported
			- name		name of the event (optional)

			The time is given in seconds starting from the epoch (1st Jan 1970).
ig.delayRS, 
			The name is optional. If there is already an existing
			event with the same name for the same process, then
			this existing event is overwritten by the new one.		
			"""
			self.__scheduler.schedule_event_absolute (time, self, name)

	@typecheck
	def __init__ (self, eui64 = "0200000102030405", clock: optional (clock.Clock) = None):
		super().__init__()
		self.__eui64 = store_data (eui64, Eui64Address)
		self.__port  = SixLowpanMessagePort (0)

		self.__scheduler = Scheduler (clock)

	# FIXME: function needed to avoid log errors
	def log_event (self, event):
		pass

	def get_scheduler (self):
		return self.__scheduler

	def get_message_port (self):
		return self.__port
	
	def reset (self):
		# clear all scheduled events
		self.__scheduler.reset()

		# generate the link local address (from the eui-64 id)
		self.__lladdr = IPv6Prefix("fe80::").make_address(self.__eui64)

		# by default we listen to two addresses:
		#  - our link-local address
		#  - the all-nodes multicast group ff02::2
		#
		# NOTE: the addresses are stored in a regular list (instead of
		# 	a set). Thus it is possible to have duplicates (which
		# 	is useful because we may register the same address with
		# 	multiple routers but we should not remove completely
		# 	the address when one router gets unreachable)
		self.__addresses = [self.__lladdr,IPv6Address("ff02::2")]


		# clear the message handlers
		self.__message_handlers = [] 
		
		# launch the processes
		self.__rdisc  = self.Process (self, self.__router_discovery_process)
		self.__icmpv6 = self.Process (self, self.__icmpv6_process)

		# dictionnary containing the process spawned for each router
		#	key:	IPv6 link local address of the router
		#	value:	register_process
		self.__router_processes = {}

		# blacklist contain all duplicated address
		self._black_list_addrDupl = []

		# blacklist contain all routeur with a full cache
		self._black_list_routeurFull = []
		


	def debug(self, msg):
		if self.config.debug:
			print (msg)
	
	def register_message (self, pattern, process):
		"""
		
		"""
		self.__message_handlers.append ((pattern, process))
	
	def run (self):
		"""Main loop
		
		The main loops monitors external events:
		 - messages received on the communication port
		 - scheduled event
		
		Then it reports the event to the adequate process.
		 - scheduled events are reported to the process that created
		   this event (by calling Process.schedule_event_xxxxxxx())
		 - messages are compared with the patterns registered (using
		   the register_message() function) and in case of a match, the
		   message is reported to the corresponding process (in case of
		   multiple matches, the message is reported multiple times)

		Events are reported to the process using the send() method
		(thus they can be received using the yield instruction).
		"""
		
		self.reset()

		while True:
			with alt:

				# match a scheduled event
				@self.__scheduler.event
				def _(ev):
					ev.process.send (ev.name)		

				# receive an IPv6 message from the communication port
				@self.__port.receive (IPv6())
				def _(value):
					# we get the IPv6 datagram
					ipv6_msg = value["pl"]["pl"]

					# filter out packets not addressed to this node
					if ipv6_msg["dst"] not in self.__addresses:
						print ("Addresses:", self.__addresses)
						print ("Ignored message (not for us):", ipv6_msg)
						return

					# check if one process is expecting this message
					# and report it if any
					for pattern, process in tuple(self.__message_handlers):
						if pattern.match (ipv6_msg):
							# report the IPv6 message to the process
							# (will be the result of the yield instruction)
							process.send (ipv6_msg)

				# receive any other message
				@self.__port.receive
				def _(value):
					print ("6lowpan implem: unexpected message:", value)
			
	def __send (self, msg):
		"""Send a message to the communication port

		This function chooses the destination (hw address) according to
		the IPv6 destination address and return True if successful.

		It will return False if the port is not connected or if there
		is no adequate route in the routing table.

		Note: it is not recommended to manipulate directly self.__port
		(eg: by calling self.__port.send()) because it may raise an
		exception if the port is not connected. This function will
		silently catch the exceptions.
		"""

		msg = msg.flatten()

		try:
			assert isinstance (msg, IPv6) # TODO: support 6lowpan & IPHC ?

			if msg["dst"][0] in (0xfe, 0xff): # FIXME: global multicast not supported
				# link-local or multicast destination
				self.__port.send (msg)
			else:
				# global destination
				# -> use the first known router
				if not self.__router_processes:
					# no route!
					return False

				self.__port.send (msg, dst = next(iter(self.__router_processes.keys())))

			return True

		except exceptions.PortNotConnected:
			return False

	def __send_ra (self, ipv6_destination_address):
		self.__send (
			IPv6 (src=self.__lladdr, dst=ipv6_destination_address) /
			ICMPv6RAdv (rlt = 30 , hp = 255 , opt =[ICMPv6SLL (hw = self.__eui64),SixPI( pf=self.PRFX1 , l = 0 ) ,]))

	def __send_rs (self, ipv6_destination_address):
		self.__send (
			IPv6 (src=self.__lladdr, dst=ipv6_destination_address) /
			ICMPv6RSol (opt =[ICMPv6SLL (hw = self.__eui64)]))




##########################################################################################################################
###################################################### ROUTER DISCOVERY PROCESS ##############################################
#########################################################################################################################



	def __router_discovery_process (self, process):
		"""Router Discovery Process
		
		This process monitors the Router Advertisement received on the
		link so as to maintain the router list up-to-date. It spawns
		one register process for each router.

		If the router list is empty, then it will send and retransmit
		Router Solicitations.
		"""

		# Register the messages to be handled by this process (RS & RA)
		#FIXME can be must precised	
		rs_template = IPv6()/ICMPv6RSol()
		ra_template = IPv6()/ICMPv6RAdv()
		
		self.register_message (rs_template, process)
		self.register_message (ra_template, process)

		# dict containing the expiration time for each router
		router_expiry_times = {}

		# number of retransmissions done so far
		retransmission_count = 0

		
		while True:

			msg = yield
							
			#-------------------- We receive a Router Solicitation from an HOTE  ------------------#
				
			if (rs_template.match (msg)):
				# we send a router solicitation to the LBR
				self.__send_rs ()



				if ( (msg["src"] in self._black_list_addrDupl) or (msg["src"] in self.__router_processes.keys()) ) :
					print("Address already used")
				
				else :
					# spawn the new process
					p = self.Process (self, self.__router_registration_process, hote_addr)
					self.__router_processes[hote_addr] = p
			
			#-------------------- We receive a Router Advertisement from a LBR  ------------------#
			if (ra_template.match (msg)):
				# we send a router advertisement to the HOTE
				self.__send_ra (msg["dst"])
				
					



##########################################################################################################################
###################################################### REGISTRATION PROCESS ##############################################
##########################################################################################################################



	def __router_registration_process (self, process, hote_addr):
		
		
		

		# Register the messages to be handled by this process (NS)	
		self.register_message (IPv6()/ICMPv6NSol(), process)

		#
		self.eui64 = "00000000000000000"


		# expiration time of the router
		# (sys.maxsize if none)
		router_expiry_time = sys.maxsize

		# boolean used to ensure that we send at most one unicast RS in
		# case the router information need to be refreshed (FIXME: shall we retransmit it ?)
		unicast_rs_sent = True

		# list of prefix info classes
		#	key:	prefix
		#	value:	PrefixInfo
		prefix_infos = {}


		# list of context info classes
		#	key:	context
		#	value:	ContextInfo
		context_infos = {}

		# list of prefix infos for which we want to register an address
		register_queue = []
			

		# PrefixInfo being registered
		pending_registration = None





		def __send_na (self, hote_addr, prefix_info):

		
			self.__send (
				IPv6(src = self.__lladdr, dst = hote_addr ) /
				ICMPv6NAdv (opt = [
					ICMPv6SLL ( hw=self.eui64 ) ,
					SixARO( lt = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 , 
					eui= ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)




		while True:
			
			print ("Reg: yield")
			msg = yield
			try:
				# TODO: wake-up to renew/revoke addresses
				now = self.__scheduler.time()
				
				print ("Reg:", now, msg)

				#-------------------- termination signal -------#

				if msg == "Kill":
					print ("Killing registration process for", hote_addr)
					
					# deconfigure the registered addresses
					for info in prefix_infos.values():
						if info.registered:
							self.__addresses.remove (info.address)

					while True:
						yield "Finished"
				
				#-------------------- it is time to refresh the router informations -------#


				#-------------------- When we receive a Neighbor Solicitation ------------------#

				elif (IPv6()/ICMPv6NSol()).match (msg):
	
					if msg[ICMPv6]["opt"][SixARO]["lt"] == 0 :
						# if the lifetime is 0, we must kill the process
						process.schedule_event_relative (-10,"Kill")
					else :
						self.eui64 = msg[ICMPv6]["opt"][SixARO]["eui"]	
						
						# we received a Neighbor Solicitation
						self.__send_na (msg["src"])


				#-------------------- some actions are needed on some prefixes ------------#
				elif msg == "PrefixInfosUpdated":
					prefix_infos_updated()

				#-------------------- some actions are needed on the context ------------#
				elif msg == "ContextUpdated" :
					context_updated()

				#-------------------- it is time to update duplicated address list ------------#
				elif msg == "blacklistAddrDuplUpdated" :
					black_list_AddrDupl_updated()

				#-------------------- it is time to update full cache router list ------------#
				elif msg == "blacklistRtrFullUpdated" :
					black_list_RouterFull_updated()

			except Exception as e:
				traceback.print_exc()

##########################################################################################################################
###################################################### ICMPv6 PROCESS(Echo-reply)  ##############################################
##########################################################################################################################



	def __icmpv6_process (self, process):
		'''ICMPv6 process
		
		- answers echo requests sent to this node
		'''
		self.register_message (IPv6()/ICMPv6EchoRequest(), process)

		while True:
			msg = yield
			self.debug("ICMPv6Process: Got an ICMPv6 Echo Request From:"+ repr(msg["src"]) +" , to: " + repr(msg["dst"]) )
			
			
			if msg["dst"] not in self._black_list_addrDupl :

				if msg["dst"][0] in (0xfe, 0xff): # linklocal or multicast
					src = self.__lladdr	#FIXME: this covers only the link-local scope
				else:
					src = msg["dst"]

				ereq = msg["pl"]

	
				self.__send (
					IPv6 ( src = src, dst = msg["src"])/
					ICMPv6EchoReply ( id = ereq["id"], seq = ereq["seq"], pl = ereq["pl"] )
				)
