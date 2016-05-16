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

from . import local_config
from . import implem
from . import implembR
from . import implemR
from .common import *

from ttproto.core import clock

class SUTActionEmulated (SUTAction):
	def run (self):
		# TODO
		pass
	
	def interrupt (self):
		pass


class SixLoWPAN_ND (Config):

	def __init__ (self, profil):
		Config.__init__ (self)

		if not local_config.EMULATION_MODE:
			self.__tap_port = SocatMessagePort("UDP:localhost:13000", Ieee802154)
		else:
			
			clock.Clock.set_instance (clock.SimulatedClock())
			
			#If we want to lunch the host implementation (implem.py)
			if( profil == "host") :
				self.__implementation = implem.SixLowpanImplementation (local_config.NUT_hwaddr)

			#If we want to lunch the router implementation (implemR.py)
			elif (profil == "router"):
				self.__implementation = implemR.SixLowpanImplementation (local_config.NUT_hwaddr)

			#If we want to lunch the border router implementation (implembR.py)
			elif (profil == "borderRouter") :
				self.__implementation = implembR.SixLowpanImplementation (local_config.NUT_hwaddr)


			self.__implementation.daemon = True
			self.__tap_port = self.__implementation.get_message_port()

			self.__implementation.start()

		class NutClass:
			pass
		NUT = NutClass()

		class TestNodeClass:
			pass
		LBR1 = TestNodeClass()
		LBR2 = TestNodeClass()
		LR1 = TestNodeClass()
		LR2 = TestNodeClass()
		HOST1 = TestNodeClass()
		HOST2 = TestNodeClass()

		NUT.addr	= IPv6Address(local_config.NUT_addr)
		NUT.lladdr	= IPv6Address(local_config.NUT_lladdr)
		NUT.hwaddr	= local_config.NUT_hwaddr
		NUT.eui64	= local_config.NUT_eui64

		LBR1.addr	= IPv6Address(local_config.LBR1_addr)
		LBR1.lladdr	= IPv6Address(local_config.LBR1_lladdr)
		LBR1.hwaddr	= local_config.LBR1_hwaddr
		LBR1.eui64	= local_config.LBR1_eui64

		LBR2.addr	= IPv6Address(local_config.LBR2_addr)
		LBR2.lladdr	= IPv6Address(local_config.LBR2_lladdr)
		LBR2.hwaddr	= local_config.LBR2_hwaddr
		LBR2.eui64	= local_config.LBR2_eui64

		LR1.addr	= IPv6Address(local_config.LR1_addr)
		LR1.lladdr	= IPv6Address(local_config.LR1_lladdr)
		LR1.hwaddr	= local_config.LR1_hwaddr
		LR1.eui64	= local_config.LR1_eui64

		LR2.addr	= IPv6Address(local_config.LR2_addr)
		LR2.lladdr	= IPv6Address(local_config.LR2_lladdr)
		LR2.hwaddr	= local_config.LR2_hwaddr
		LR2.eui64	= local_config.LR2_eui64

		HOST1.addr	= IPv6Address(local_config.HOST1_addr)
		HOST1.lladdr	= IPv6Address(local_config.HOST1_lladdr)
		HOST1.hwaddr	= local_config.HOST1_hwaddr
		HOST1.eui64	= local_config.HOST1_eui64

		HOST2.addr	= IPv6Address(local_config.HOST2_addr)
		HOST2.lladdr	= IPv6Address(local_config.HOST2_lladdr)
		HOST2.hwaddr	= local_config.HOST2_hwaddr
		HOST2.eui64	= local_config.HOST2_eui64

		TIMER1 = local_config.TIMER1
		TIMER2 = local_config.TIMER2
		SLEEP1 = local_config.SLEEP1

		PRFX1 = local_config.PRFX1
		PRFX2 = local_config.PRFX2

		PANID = local_config.PANID

		self["NUT"] = NUT
		self["LBR1"] = LBR1
		self["LBR2"] = LBR2
		self["LR1"] = LR1
		self["LR2"] = LR2

		self["TIMER1"]=TIMER1
		self["TIMER2"]=TIMER2
		self["SLEEP1"]=SLEEP1

		self["PRFX1"]=PRFX1
		self["PRFX2"]=PRFX2

		self["PANID"]=PANID

		self["HOST1"] = HOST1
		self["HOST2"] = HOST2

		self["action"] = SUTActionEmulated if local_config.EMULATION_MODE else SUTActionManual

	def __enter__ (self):
		link1 = SixLowpanMessagePort (self["PANID"], self.__tap_port)
		self["link1"] = link1

		if local_config.EMULATION_MODE:
			clock.Clock.get_instance().reset()

			self.__implementation.reset()

			clock.Clock.get_instance().start()

		
	def __exit__ (self, a, b, c):
		self["link1"].disconnect()

		if local_config.EMULATION_MODE:
			clock.Clock.get_instance().reset()
