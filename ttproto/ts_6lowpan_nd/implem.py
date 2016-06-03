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
	def __init__ (self, eui64 = "0200000001020304", clock: optional (clock.Clock) = None, compression = False):
		super().__init__()
		self.__eui64 = store_data (eui64, Eui64Address)
		self.__port  = SixLowpanMessagePort (0, compression = compression)

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
		#  - the all-nodes multicast group ff02::1
		#
		# NOTE: the addresses are stored in a regular list (instead of
		# 	a set). Thus it is possible to have duplicates (which
		# 	is useful because we may register the same address with
		# 	multiple routers but we should not remove completely
		# 	the address when one router gets unreachable)
		self.__addresses = [self.__lladdr, IPv6Address("ff02::1")]


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


	def __retransTimer ( self, x ):
		if x < 3:
			return 10
		else:
			return min ( 2 * self.__retransTimer(x - 1) , 60 ) 


	def __send_rs (self, ipv6_destination_address):
		self.__send (
			IPv6 (src=self.__lladdr, dst=ipv6_destination_address) /
			ICMPv6RSol (opt =[ICMPv6SLL (hw = self.__eui64)]))

	def __send_ns (self, router_addr, prefix_info):

		# compute the lifetime to be used
		if not prefix_info.valid():
			lifetime = 0
		else:
			lifetime = prefix_info.choose_ns_lifetime()

			assert lifetime > 0

		self.__send (
			IPv6(src = prefix_info.address , dst = router_addr ) /
			ICMPv6NSol ( tgt=router_addr,opt = [
					ICMPv6SLL ( hw=self.__eui64 ) ,
					SixARO(eui= self.__eui64, lt = lifetime)
					]
				)
			)


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

		# Register the messages to be handled by this process (RA)	
		self.register_message (IPv6()/ICMPv6RAdv(), process)

		# dict containing the expiration time for each router
		router_expiry_times = {}

		# number of retransmissions done so far
		retransmission_count = 0

		# Schedule a event named "SendRS" to wake up when it is time to send a new Router Solicitation
		# (we delay the first RS so as not to send it before the beginning of the testcase)
		process.schedule_event_relative (self.config.DelayRS, "SendRSol")



		#It update the blacklist of router cache full
		def black_list_RouterFull_updated():
			"""This function shall be called each time one
			Router address is added to the blacklist.
			"""
			
			if self._black_list_routeurFull[len(self._black_list_routeurFull)-1] in router_expiry_times :
				router_expiry_times.pop(self._black_list_routeurFull[len(self._black_list_routeurFull)-1])



		while True:
			#-------------------- Schedule an expiration event if needed ------------------#
			if router_expiry_times:
				process.schedule_event_absolute (min (router_expiry_times.values()), "Expiry")

			print ("Disc: yield", router_expiry_times)
			msg = yield
			try:	
				#-------------------- Check for expired routers ------------------#
				now = self.__scheduler.time()

				print ("Disc:", now, msg)
				
				for rtr, expiry in tuple (router_expiry_times.items()):
					if expiry <= now:
						# kill the existing process
						print("Kill the existing process")
						rtr_process = self.__router_processes[rtr]

						kill_result = rtr_process.send("Kill")

						assert kill_result == "Finished"

						# remove it from the lists
						self.__router_processes.pop (rtr)
						router_expiry_times.pop (rtr)
						
						if not router_expiry_times:
							# the router list is now empty
							# -> restart sending multicast Router Solicitations
							retransmission_count = 0
							process.schedule_event_relative (0, "SendRSol")
					

				
				#-------------------- Event to send a Router Sollicitation ------------------#
				
				if msg == "SendRSol":
					# we only send a router solicitation when the router list is empty


					if not router_expiry_times:
						# We send the Router Sollicitation
						self.__send_rs ("ff02::2")

						retransmission_count += 1

						# schedule the retransmission of the next RS

						# --we must retransmit 3 packet during 10 seconds, then
						# --we SHOULD do binary exponential backoff of the retransmission for the others
						# timer for each subsequent retransmission
						if retransmission_count <= 2:
							delay = 10
						elif retransmission_count == 3:
							delay = 20
							
						elif retransmission_count == 4:
							delay = 40
						else:
							delay = 60

						process.schedule_event_relative (delay, "SendRSol")

						self.debug("RdiscProcess: RS sending scheduled in %d seconds." % delay)


				#-------------------- it is time to update full cache router list ------------#
				if msg == "blacklistRtrFullUpdated" :
					black_list_RouterFull_updated()

				

				#-------------------- When we receive a Router Advertisement ------------------#

				if (IPv6()/ICMPv6RAdv()).match (msg):
					# we received a Router Advertisement

					if not (IPv6()/ICMPv6RAdv(opt = Superset (ICMPv6OptionList , [ ICMPv6PI() ] ))).match(msg):
						print("The option ICMPv6PI is not contained in this Router Advertisement")
						continue

					router_addr = msg["src"]

					assert (router_addr in router_expiry_times) == (router_addr in self.__router_processes) # these two dict must always contain the same keys
					#We must check that the routeur address is not in the blacklist router
					addr_is_ok = True

					for router_full in self._black_list_routeurFull :
						if router_full == router_addr :
							addr_is_ok = False
							
					if addr_is_ok:	

						if router_addr not in router_expiry_times:
							# unknown router
							# -> start a new register process

							# spawn the new process
							p = self.Process (self, self.__router_registration_process, router_addr)
							self.__router_processes[router_addr] = p

							# send the RA message to the process
							p.send (msg)

						# compute the expiration time
						router_expiry_times[router_addr] = now + msg["pl"]["rlt"]

			except Exception as e:
				traceback.print_exc()




		
		



##########################################################################################################################
###################################################### REGISTRATION PROCESS ##############################################
##########################################################################################################################




	def __router_registration_process (self, process, router_addr):
		
		ra_template = IPv6(src = router_addr)/ICMPv6RAdv()
		na_template = IPv6(src = router_addr)/ICMPv6NAdv(opt = Superset(ICMPv6OptionList, [SixARO(eui=self.__eui64,len=2)]))

		self.register_message (ra_template, process)
		self.register_message (na_template, process)

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

		
		#It update the blacklist of address duplicated
		def black_list_AddrDupl_updated():
			"""This function shall be called each time one
			address is added to the blacklist.
			"""

			# we stock the last element insert (maybe a little hard...)
			addr_dupl = self._black_list_addrDupl[len(self._black_list_addrDupl)-1]


			#we get the prefix in the prefix info list
			for pref in tuple ( prefix_infos.values()):
				if addr_dupl == pref.address :
					prefix_tosend = pref
				
			for blackaddr in self._black_list_addrDupl :
				if blackaddr==addr_dupl :
					#We affect now to expiry_time_valid to provoc a lifetime to 0
					prefix_tosend.expiry_time_valid=now
					self.__send_ns(router_addr,prefix_tosend)
					break


		def context_updated (mycontext):
				
			for cont in tuple (context_infos.values()):

				# if our context match in context_infos entry
				if mycontext.contextId == cont.contextId :
				
					if mycontext.valid():

						#Update of context values
						cont.c = mycontext.c
						cont.pf = mycontext.pf

						# Compute the new expiry time
						cont.refresh(lt,now)

					else :
						# The context is no valid

						# -> delete it
						context_infos.pop (cont.contextId)

			
			# schedule the next PrefixInfoUpdated event
			process.schedule_event_absolute (mycontext.expiry_time_valid, "ContextUpdated")

				

	




		def prefix_infos_updated ():
			"""This function shall be called each time one
			prefix information may have changed.
			"""

			wakeup_time = sys.maxsize

			for info in tuple (prefix_infos.values()):

				if info.should_register():
					# Valid prefix (that we should register)
					# or for which our registration is about to expire

					# schedule its registration
					if info not in register_queue:
						register_queue.append (info)

				if info.registration_expired():
					# Expired registration (registered address no longer valid)

					assert info.registered

					# deconfigure the address
					self.__addresses.remove (info.address)
					info.registered = False

					print ("Removing address %s" % info.address) 

				if not info.valid():
					# The prefix is no longer valid

					# -> delete it
					prefix_infos.pop (info.prefix)

				if info.registered:
					if info.ns_sent or info in register_queue:
						# next action is expiration
						my_wakeup_time = info.expiry_time_registration
						print ("my next expiration", my_wakeup_time)
					else:
						# next action is to renew the registration
						my_wakeup_time = info.expiry_time_registration - self.config.AddressRefreshTime
						print ("my next renew", my_wakeup_time)

					if my_wakeup_time < wakeup_time:
						wakeup_time = my_wakeup_time

			# schedule the next PrefixInfoUpdated event
			process.schedule_event_absolute (wakeup_time, "PrefixInfosUpdated")


		def schedule_unicast_rs():
			"""Compute the time at which we must wake up to send a
			new unicast RS to refresh the router information and
			schedule the event"""
			
			if not unicast_rs_sent:
				expiry_time = router_expiry_time

				for info in prefix_infos.values():
					expiry_time = min (expiry_time,
						info.expiry_time_valid,
						info.expiry_time_preferred)

				refresh_time = expiry_time - self.config.routerRefreshTime

				process.schedule_event_absolute (refresh_time, "SendRSol")

				print ("Will send a unicast RS to %s in %d seconds" % (str(router_addr), refresh_time))


		class ContextInfo:
			def __init__ (self, context,contextId,c,pf, lt, current_time):
				
				# IPv6 context
				self.context  = context
				self.contextId  = contextId
				self.c = c
				self.pf = pf
				self.lt = lt
				
				self.refresh (lt, current_time)
				#print("CONTEXT = '%s' c = '%d' clen= '%d' pf= '%s' lt='%d' " % (self.context 							self.contextId,self.c,self.clen,self.pf,self.lt))

			def refresh (self, lt, current_time):

				# Expiration time of the prefix (Valid Lifetime)
				self.expiry_time_valid = now + self.lt
				
				
			def valid (self):
				"""Return True of the context is still valid"""
				return now < self.expiry_time_valid

			


		class PrefixInfo:
			def __init__ (self, prefix, pi_option, current_time, hw_identifier):

				assert prefix == IPv6Prefix (pi_option["Prefix"], pi_option["PrefixLength"])

				# IPv6 prefix
				self.prefix  = prefix

				# IPv6 address generated for this prefix
				self.address = prefix.make_address (hw_identifier)

				# State variable indicating that this address
				# is registered with the router and configured
				# on this node
				self.registered  = False

				# State variable set to True when a NS has been
				# sent to renew the registration of the address
				self.ns_sent = False

				# Expiration time of the current registration
				self.expiry_time_registration = 0

				self.refresh (pi_option, current_time)

			def refresh (self, pi_option, current_time):

				assert self.prefix == IPv6Prefix (pi_option["Prefix"], pi_option["PrefixLength"])

				# Expiration time of the prefix (Valid Lifetime)
				self.expiry_time_valid     = now + pi_option["ValidLifetime"]
				#TODO: rename PreferedLifetime as PreferredLifetime

				# Expiration time of the prefix (Preferred Lifetime)
				self.expiry_time_preferred = now + pi_option["PreferedLifetime"]




			def valid (self):
				"""Return True of the prefix is still valid (according to the Valid Lifetime in the previous RA)"""
				return now < self.expiry_time_valid

			def preferred (self):
				"""Return True of the prefix is still preferred (according to the Preferred Lifetime in the previous RA)"""
				return now < self.expiry_time_preferred

			def should_register (info):
				"""Return true if we need to send a NS to register/extend the registration of the address"""

				#if the address is in the blacklist -> return false 
				for black_addr in self._black_list_addrDupl : 
					if black_addr==self.address :
						return false

				if not info.registered:
					return info.valid()

				else:
					return not info.ns_sent and ((info.expiry_time_registration - self.config.AddressRefreshTime ) <= now < info.expiry_time_registration)

			def registration_expired (self):
				"""Return true if the currently registered address has expired"""
				return self.registered and (now >= self.expiry_time_registration)

			def choose_ns_lifetime (info):
				"""Returns the desired registration lifetime in minutes (to be inserted in the NS).
				
				This function also stores the requested	expiration time internally
				in info.expiry_time_registration_requested.
				"""

				# TODO: ensure it is not less than the router lifetime
				lifetime = min (	info.expiry_time_valid     - now,
						info.expiry_time_preferred - now) // 60

				# minimum lifetime will be 1 minute
				if lifetime <= 0:
					lifetime = 1

				# remember the requested expiration time
				info.expiry_time_registration_requested = min (
					now + lifetime * 60,
					info.expiry_time_valid
				)

				print ("Requested lifetime for %s is %d min (expires at %d)" % (info.address, lifetime, info.expiry_time_registration_requested))

				return lifetime


		while True:
			print ("Reg: yield")
			msg = yield
			try:
				# TODO: wake-up to renew/revoke addresses
				now = self.__scheduler.time()
				
				print ("Reg:", now, msg)

				#-------------------- termination signal -------#

				if msg == "Kill":
					print ("Killing registration process for", router_addr)
					
					# deconfigure the registered addresses
					for info in prefix_infos.values():
						if info.registered:
							self.__addresses.remove (info.address)

					while True:
						yield "Finished"
				
				#-------------------- it is time to refresh the router informations -------#

				elif msg == "SendRSol":
					if not unicast_rs_sent:
						print( "send RS", router_addr)
						self.__send_rs (router_addr)
						unicast_rs_sent = True

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



				#-------------------- we received a Router Advertisement ------------------#

				elif (ra_template.match (msg)):
					# we received a Router Advertisement
					ra = msg["pl"]

					router_expiry_time = now + ra['rlt']

					# parse the Prefix Information options
					for pio in filter (lambda x: isinstance(x, ICMPv6PI), ra["opt"]):

						# Ignore PI options with the OnLink flag set
						if pio["l"] == 1:
							print("The option ICMPv6 has the bit l set to 1 !")
							continue

						prefix = IPv6Prefix (pio["Prefix"], pio["PrefixLength"])
						
						if prefix not in prefix_infos:
							# this is a new prefix!
							info = PrefixInfo (prefix, pio, now, self.__eui64)
							prefix_infos[prefix] = info
						else:
							# unknown prefix
							# -> refresh it
							info = prefix_infos[prefix]
							info.refresh (pio, now)

					#Context Informations

					if (IPv6()/ICMPv6RAdv(opt = Superset (ICMPv6OptionList,[ SixCO()] ))).match(msg) :
						
						
						context = msg["pl"]["opt"][SixCO]
						#ContextId is the key for context_infos
						contextId = msg["pl"]["opt"][SixCO]["cid"]
						compress = msg["pl"]["opt"][SixCO]["c"]
						contextPrefix = msg["pl"]["opt"][SixCO]["pf"]
						contextLt = msg["pl"]["opt"][SixCO]["lt"]
						

						if context not in context_infos:
							#this is a new context
							cont = ContextInfo(context,contextId,compress,contextPrefix,contextLt,now)
							context_infos[contextId] = cont
						else:
							# unknown context
							# -> refresh it
							cont = context_infos[contextId]
							info.refresh (lt, now)

							# Update information about the context
							context_updated(cont)
						


					# schedule next actions on prefix infos
					prefix_infos_updated()
					
					# schedule an event for sending a refresh unicast RS
					unicast_rs_sent = False
					schedule_unicast_rs()

				

				#-------------------- Address Registration ------------------#

				if pending_registration:
					finished = False
					

					if na_template.match(msg):
						# We received the Neighbor Advertisemen
						finished = True
						#FIXME: maybe check that the destination address is valid (which one shall be used ???)
						print("MATCH")
						aro = msg["pl"]["opt"][SixARO]
						
						if aro["Status"] == 0:
							# Successful registration !
							pending_registration.registered = True
							pending_registration.ns_sent = False

							# configure the ipv6 address on the node
							self.__addresses.append (pending_registration.address)
							print ("Successfully registered", pending_registration.address)
							print ("Addresses:", self.__addresses)

							prefix_infos_updated()
							
						elif aro["Status"] == 1:
						#A Status code of one indicates that the Address is duplicated
						# We should append it in the blacklist
							print("Status -> 1")
							self._black_list_addrDupl.append(pending_registration.address)

						#We send a message to all processes for an updating but not the current process
							
							for proc in tuple (self.__router_processes .values()):
									proc.schedule_event_relative (0,"blacklistAddrDuplUpdated")

							
						elif aro["Status"] == 2:
							#A Status code of two indicates that the Neighbor Cache of that router
  							#is full.  In this case the host SHOULD remove this router from its
 							#default router list and attempt to register with another router.  If
   							#the host has no more default routers it needs to revert to sending Router Solicitations

							# We should append it in the blacklist
							self._black_list_routeurFull.append(router_addr)
							#We kill the process
							process.schedule_event_relative (-10,"Kill")

							#We send a message to all processes for an updating of the blacklist Routeur
							self.__rdisc.schedule_event_relative (0,"blacklistRtrFullUpdated")
							

						else :
							print("Status !=0,1,2")

					elif msg == "TimeoutNS":
						# registration failed
						finished = True

					if finished:
						# registration terminated !

						try:
							register_queue.remove (pending_registration)
						except ValueError:
							pass
											
						pending_registration = None

				if not pending_registration: # NOT ELSE !!!
					
					# start a new registration !
					
					while register_queue:
						pending_registration = register_queue.pop()

						if pending_registration.should_register():

							assert pending_registration.valid()
							
							# Send a neighbour solicitation
							self.__send_ns (router_addr, pending_registration)

							pending_registration.ns_sent = True
							pending_registration.expiry_time_registration = pending_registration.expiry_time_registration_requested

							# schedule a 5 second timeout (if successful)
							process.schedule_event_relative (5, "TimeoutNS")

							break
					
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
