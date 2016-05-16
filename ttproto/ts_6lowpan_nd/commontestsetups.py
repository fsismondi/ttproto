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

from .common import *

#FIXME: remove this ... already in common.py but not working ..
from ttproto.core.list			import *
from ttproto.core.templates 		import *

def superop ( opt ):
	return Superset (ICMPv6OptionList , opt)

################################################################################
# CommonTestSetup_1_1
################################################################################

def CommonTestSetup_1_1( lbr , nut , prfx , timer1, link, routerlt = 60 , prefixlt = 60):
	#pass

	log ("Entering common test setup 1.1")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	ra = pack (
		IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
		ICMPv6RAdv( rlt = routerlt, opt = [
			ICMPv6SLL( hw=lbr.hwaddr ) ,
			SixPI( pf=prfx , vlt = prefixlt )
			]
		)
	)

	ereq = pack(
		IPv6 (src = lbr.addr, dst = nut.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-common-test-setup-1.1"
	)
	t.start(timer1)
	
	link.receive (
		IPv6( src = nut.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	link.send(ra)
	t.start(timer1)

	with alt:	#FIXME: removable
		@link.receive (
			IPv6( src = nut.addr , dst = lbr.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=nut.hwaddr ) ,
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt  = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0,
						eui = value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link.send(na)

	link.send(ereq)
	t.start(timer1)

	link.receive ( SixLowpanIPv6()/IPv6( src=nut.addr , dst = lbr.addr  )/ICMPv6EchoReply() )

	t.stop()

	log ("Common Test setup 1.1 terminated")



################################################################################
# CommonTestSetup_1_1b
################################################################################

def CommonTestSetup_1_1b( lbr , nut , prfx , timer1, link,  routerlt = 60 , prefixlt = 60 , contextlt = 60):
	#pass
	log ("Entering common test setup 1.1b")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	ra = pack (
		IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
		ICMPv6RAdv( rlt = routerlt, opt = [
			ICMPv6SLL( hw=lbr.hwaddr ) ,
			SixPI( pf=prfx , vlt = prefixlt ) ,
			SixCO( c=1 , clen=64, pf=prfx , lt=contextlt)
			]
		)
	)

	ereq = pack(
		IPv6 (src = lbr.addr, dst = nut.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-common-test-setup-1.1b"
	)

	t.start(timer1)

	link.receive (
		IPv6( src = nut.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	link.send(ra)
	t.start(timer1)

	with alt:	#FIXME: removable
		@link.receive (
			IPv6( src = nut.addr , dst = lbr.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=nut.hwaddr ) ,
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 ,
						eui = value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link.send(na)

	link.send(ereq)
	t.start(timer1)

	link.receive ( SixLowpanIPv6()/IPv6( src=nut.addr , dst = lbr.addr  )/ICMPv6EchoReply() )

	log ("Common Test setup 1.1b terminated")


################################################################################
# CommonTestSetup_1_2
################################################################################

def CommonTestSetup_1_2( lbr , nut , prfx , timer1, link,  routerlt = 60 , prefixlt = 60 , contextlt = 60):
	#pass

	log ("Entering common test setup 1.2")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	ra = pack (
		IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
		ICMPv6RAdv( rlt = routerlt, opt = [
				ICMPv6SLL( hw=lbr.hwaddr ),
				SixABRO(lbr=lbr.addr) ,
				SixPI( pf=prfx , vlt = prefixlt )
			]
		)
	)


	ereq = pack(
		IPv6 (src = lbr.addr, dst = nut.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-common-test-setup-1.2"
	)

	t.start(timer1)
	link.receive (
		IPv6( src = nut.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link.send(ra)



	t.start(timer1)
	with alt:	#FIXME: removable
		@link.receive (
			IPv6( src = nut.addr , dst = lbr.lladdr ) /
			ICMPv6NSol( tgt =lbr.lladdr, opt = superop ( [
				ICMPv6SLL( hw = nut.hwaddr ) ,
				SixARO(eui=nut.hwaddr)
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 )
					]
				)
			)
			link.send(na)

	t.start(timer1)
	link.send(ereq)
	link.receive ( SixLowpanIPv6()/IPv6( src=nut.addr , dst = lbr.addr  )/ICMPv6EchoReply() )
	t.stop()

	log ("Common Test setup 1.2 terminated")


################################################################################
# CommonTestSetup_1_2b
################################################################################

def CommonTestSetup_1_2b( lbr , nut , prfx , timer1, link,  routerlt = 60 , prefixlt = 60 , contextlt = 60):
	#pass

	log ("Entering common test setup 1.2b")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	ra = pack (
		IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
		ICMPv6RAdv( rlt = routerlt,
			opt = [
				SixABRO(lbr=lbr.addr) ,
				SixCO(lt =contextlt , clen = 1 ,c = 1, pf=prfx),
			]
		)
	)

	na = pack (
		IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
		ICMPv6NAdv( opt = [
			ICMPv6SLL( hw=lbr.hwaddr ) ,
			SixARO( lt= contextlt , st = 0 )
			]
		)
	)

	ereq = pack(
		IPv6 (src = lbr.addr, dst = nut.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-common-test-setup-1.2b"
	)

	t.start(timer1)

	link.receive (
		IPv6( src = nut.addr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	link.send(ra)
	t.start(timer1)

	with alt:	#FIXME: removable
		@link.receive (
			IPv6( src = nut.addr , dst = lbr.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw = nut.hwaddr ) ,
				SixARO()
				] )

			)
		)
		def _(value):
			na = pack (
				IPv6( src = lbr.lladdr , dst = nut.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 )
					]
				)
			)
			link.send(na)

	link.send(ereq)
	t.start(timer1)

	link.receive ( SixLowpanIPv6()/IPv6( src=nut.addr , dst = lbr.addr  )/ICMPv6EchoReply() )

	log ("Common Test setup 1.2b terminated")

################################################################################
# CommonTestSetup_1_3
################################################################################
#TODO
def CommonTestSetup_1_3( host , nut , prfx , timer1, link,  routerlt = 60 , prefixlt = 60):
	#pass
	
	log ("Entering common test setup 1.3")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	log ("Common Test setup 1.3 terminated")


################################################################################
# CommonTestSetup_1_3b
################################################################################
#TODO
def CommonTestSetup_1_3b( host , nut , prfx , timer1, link,  routerlt = 60 , prefixlt = 60 , contextlt = 60):
	#pass
	log ("Entering common test setup 1.3b")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	log ("Common Test setup 1.3b terminated")


################################################################################
# CommonTestSetup_1_4
################################################################################

def CommonTestSetup_1_4(lbr , host,nut, prfx , timer1, link,  routerlt = 60 , prefixlt = 60, contextlt = 60  ):
	#TODO To modified to know if :
		# - the NUT is a LBR -> CommonTestSetup_1_3()
		# - the NUT is a LR -> CommonTestSetup_1_2()

	log ("Entering common test setup 1.4")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	#if nut==lbr:
	#	CommonTestSetup_1_3()

	#elif nut ==LR1 :
	#CommonTestSetup_1_2(lbr , nut , prfx , timer1, link,  routerlt, prefixlt, contextlt)

	log ("Common Test setup 1.4 terminated")


################################################################################
# CommonTestSetup_1_4b
################################################################################

def CommonTestSetup_1_4b(lbr , host ,nut, prfx , timer1, link,  routerlt = 60 , prefixlt = 60 , contextlt = 60 ):
	#TODO To modified to know if :
		# - the NUT is a LBR -> CommonTestSetup_1_3b()
		# - the NUT is a LR -> CommonTestSetup_1_2b()

	log ("Entering common test setup 1.4b")
	t = Timer()

	unexpected_packets.activate( link )
	timeout.activate( t )

	#if nut==lbr:
	#	CommonTestSetup_1_3b()

	#elif nut ==LR1 :
	#	CommonTestSetup_1_2b(lbr , nut , prfx , timer1, link,  routerlt, prefixlt, contextlt)


	log ("Common Test setup 1.4b terminated")

#########################################################################
# End # End # End # End # End # End # End # End # End # End # End # End #	
#########################################################################
