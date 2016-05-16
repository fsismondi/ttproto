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
from . import implemR
################################################################################
# Dummy init
################################################################################

@testcase(SixLoWPAN_ND)
def init( link1 ):
	ereq = pack (
		IPv6 (src = "::", dst = "::" ),
		ICMPv6EchoRequest(),
		"init()"
	)
	link1.send(ereq)

################################################################################
# Test_LPND_1.3.1
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_1(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=NUT.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Router Solicitation" )	
	link1.send(rs)
	t.start(TIMER1)

	step (3, "We expect a Router Advertisement" )	
	link1.receive (
		IPv6( dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixPI( l=0 )
			] )
		)
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.3.2a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_2a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Router Solicitation" )	
	link1.send(rs)
	t.start(TIMER1)

	step (3, "We expect a Router Advertisement" )	
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( )
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.3.2b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_2b(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Router Solicitation" )	
	link1.send(rs)
	t.start(TIMER1)

	step (3, "We expect a Router Advertisement" )	
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv(  opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr )
			] )
		)
	)
	set_verdict("pass")



################################################################################
# Test_LPND_1.3.2c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_2c(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)

	ereq = pack (
		IPv6 (src = HOST1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.3.2c"
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "NODE1 sends an ICMPv6 Router Solicitation" )
	link1.send(rs)

	step (3, "We send an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t2.start(TIMER1)
	with alt:

		@link1.receive ( IPv6( src=NUT.addr , dst = HOST1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1.3.3a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_3a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO( Length = 9 , eui = HOST1.eui64 )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and don't expect any Answer" )
	link1.send(ns)
	t.start(TIMER1)

	with alt:
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( )
		)
		def _():
			set_verdict ("fail")
		@t.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.3.3b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_3b(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO( st = 80 , eui = HOST1.eui64 )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and don't expect any Answer" )
	link1.send(ns)
	t.start(TIMER1)

	with alt:
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( )
		)
		def _():
			set_verdict ("fail")
		@t.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.3.3c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_3c(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO( st = 0 , eui = HOST1.eui64 )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement without any ARO" )
	link1.send(ns)
	t.start(TIMER1)

	with alt:
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  )
				] )
			)
		)
		def _():
			set_verdict ("fail")

		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( opt = [] )
		)
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.3.3d
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_3d(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = HOST1.eui64 )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement without any ARO" )
	link1.send(ns)
	t.start(TIMER1)

	with alt:
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO( )
				] )
			)
		)
		def _():
			set_verdict ("fail")

		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6NAdv( opt = [] )
		)
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.3.4a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_4a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst=NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = HOST1.eui64 ),
			ICMPv6SLL( hw=HOST1.hwaddr ) 
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement without any ARO" )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = HOST1.eui64 )
				] )
			)
		)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.3.4b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_4b(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000000" ) ,
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 0 " )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = "1234567890000000")
				] )
			)
		)
	set_verdict ("pass")

	step (3, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 0 " )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = "1234567890000000" )
				] )
			)
		)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.3.4c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_4c(NUT , TIMER1 , HOST1 , HOST2, LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000000" ) ,
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)

	ns2 = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000011" ),
			ICMPv6SLL( hw=HOST2.hwaddr ) 
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 0 " )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = "1234567890000000" )
				] )
			)
		)
	set_verdict ("pass")

	step (3, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 1 " )
	link1.send(ns2)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 1  , eui = "1234567890000011" )
				] )
			)
		)
	set_verdict ("pass")


################################################################################
# Test_LPND_1.3.5a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_5a(NUT , TIMER1 , HOST1 , HOST2 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000000" ),
			ICMPv6SLL( hw=HOST1.hwaddr ) 
			]
		)
	)

	ns2 = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000011" ) ,
			ICMPv6SLL( hw=HOST2.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 0 " )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = "1234567890000000" )
				] )
			)
		)
	set_verdict ("pass")

	step (3, "We send an Neighboor Solicitation and a expect Neighboor advertisement with the IPv6 destination field set to " +HOST2.lladdr)
	link1.send(ns2)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr , dst = "" ) / #TODO: dst address derived from EUI64
			ICMPv6NAdv( opt = superop ( [
				SixARO()
				] )
			)
		)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.3.5b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_5a(NUT , TIMER1 , HOST1 , HOST2 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000000" ),
			ICMPv6SLL( hw=HOST1.hwaddr ) 
			]
		)
	)

	ns2 = pack (
		IPv6( src = PRFX1+"42:1" , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			SixARO( eui = "1234567890000011" , lt = 38) ,
			ICMPv6SLL( hw=HOST2.hwaddr )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send an Neighboor Solicitation and a expect Neighboor advertisement with an ARO with a st = 0 " )
	link1.send(ns)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6NAdv( opt = superop ( [
				SixARO(  st = 0  , eui = "1234567890000000" )
				] )
			)
		)
	set_verdict ("pass")

	step (3, "We send an Neighboor Solicitation and a expect Neighboor advertisement with the lifetime field set to 38" )
	link1.send(ns2)
	t.start(TIMER1)

	link1.receive (
			IPv6( src = NUT.lladdr , dst = "" ),
			ICMPv6NAdv(  opt = superop ( [
				SixARO( st = 1 , eui = "1234567890000011" , lt = 38)
				] )
			)
		)
	set_verdict ("pass")


################################################################################
# Test_LPND_1.3.6a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_6a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):


	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns1 = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO(lt = 1 , eui = HOST1.eui64  )
			]
		)
	)
	
	ns2 = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO(lt = 0 , eui = HOST1.eui64  )
			]
		)
	)
	
	ereq1 = pack (
		IPv6 (src = NUT.addr, dst = HOST1.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.3.6a-1"
	)

	ereq2 = pack (
		IPv6 (src = NUT.addr, dst = HOST1.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.3.6a-2"
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Neighboor Solicitation with an ARO with a lifetime set to 1 (60 seconds) and we expect a Neighboor Solicitation" )	
	link1.send(ns1)
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr ) /
		ICMPv6NAdv( opt = superop ( [
			SixARO(  st = 0  , lt = 1 ,  eui = HOST1.eui64  )
			] )
		)
	)
	set_verdict("pass")

	step (3, "We sends an ICMPv6 Echo Request. We expect an ICMPv6 Echo Reply" )
	link1.send(ereq1)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = HOST1.addr ) / ICMPv6ERep() )
	set_verdict("pass")


	step (4, "We send a Neighboor Solicitation with an ARO with a lifetime set to 0 (0 seconds) and  we expect a Neighboor Solicitation" )	
	link1.send(ns2)
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr ) /
		ICMPv6NAdv( opt = superop ( [
			SixARO(  st = 0  , lt = 0 , eui = HOST1.eui64 ) 
			] )
		)
	)
	set_verdict("pass")

	step (5, "We sends an ICMPv6 Echo Request. We expect an no ICMPv6 Echo Reply ")
	link1.send(ereq2)
	t.stop()
	t2.start(TIMER2)

	with alt:
		@link1.receive( IPv6( src = NUT.addr , dst= HOST1.addr ) / ICMPv6ERep() )
		def _():
			set_verdict("fail")

		@t2.timeout()
		def _():
			set_verdict("pass")


################################################################################
# Test_LPND_1.3.7a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_7a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO(lt = 1 ,  eui = HOST1.eui64  )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Neighboor Solicitation with an ARO we expect a Neighboor Solicitation" )	
	link1.send(ns)
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr ) /
		ICMPv6NAdv( opt = superop ( [
			SixARO(  st = 0  , lt = 0 , eui = HOST1.eui64 )
			] )
		)
	)
	set_verdict("pass")

	step (3, "NUT action")
	action ("Order the NUT to emit an ICMPv6 Echo Request to %s" % HOST1.addr)

	t.start(TIMER1)
	step (4, "We expect an ICMPv6 Echo Request with the link layer address set to HOST1" )
	link1.receive (	IPv6( src = NUT.addr , dst=HOST1.addr) / ICMPv6EReq() ,	HOST1.hwaddr )
	set_verdict("pass")


################################################################################
# Test_LPND_1.3.7b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_7b(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "NUT action")
	action ("Order the NUT to emit an ICMPv6 Echo Request to %s" % HOST1.addr)
	
	step (3, "We expect an ICMPv6 Echo Request with the link layer address set to LBR1" ) #TODO: LBR: case ?
	t.start(TIMER1)
	link1.receive (	IPv6( src = NUT.addr , dst=HOST1.addr) / ICMPv6EReq() , LBR1.hwaddr )
	set_verdict("pass")


################################################################################
# Test_LPND_1.3.7c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_7c(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO(lt = 1 ,  eui = HOST1.eui64  )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a Neighboor Solicitation with an ARO we expect a Neighboor Advertisement with an ARO" )	
	link1.send(ns)
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr ) /
		ICMPv6NAdv( opt = superop ( [
			SixARO(  st = 0  , lt = 1 , eui = HOST1.eui64 )
			] )
		)
	)
	set_verdict("pass")

	step (3, "We wait for 60 seconds" )
	t.start (60)
	t.timeout()

	step (4, "NUT action")
	action ("Order the NUT to emit an ICMPv6 Echo Request to %s" % HOST1.addr)

	t.start(TIMER1)
	step (5, "We expect an ICMPv6 Echo Request with the link layer address set to LBR1" )  #TODO: LBR: case ?
	link1.receive (	IPv6( src = NUT.addr , dst=HOST1.addr) / ICMPv6EReq() , LBR1.hwaddr )
	set_verdict("pass")

################################################################################
# Test_LPND_1.3.8a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_8a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq = pack (
		IPv6 (src = NUT.lladdr, dst = HOST1.lladdr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.3.8a"
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "HOST1 sends an ICMPv6 Echo Request to the solicited-node multicast address of the NUT" )
	link1.send(ereq)

	step (3, "We expect an ICMPv6 Echo Reply" )
	t.start(TIMER1)
	link1.receive(
		IPv6 ( src = NUT.lladdr , dst = HOST1.lladdr )  /
		ICMPv6ERep()
		)
	set_verdict("pass")
	

################################################################################
# Test_LPND_1.3.8b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_8b(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt =  [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "HOST1 sends an ICMPv6 Neigboor solicitation to the solicited-node multicast address of the NUT" )
	link1.send(ns)

	step (3, "We expect an ICMPv6 Neigboor advertisement" )
	t.start(TIMER1)
	link1.receive(
		IPv6 ( src = NUT.lladdr , dst = HOST1.addr )  /
		ICMPv6NAdv()
		)
	set_verdict("pass")


################################################################################
# Test_LPND_1.3.9
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_9(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ns = pack (
		IPv6( src = HOST1.addr , dst = NUT.lladdr ) ,
		ICMPv6NSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr ) ,
			SixARO(lt = 1 ,  eui = HOST1.eui64  )
			]
		)
	)

	step (1, "We perform the common test setup 1.4" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a neighboor solicitation with an Address Registration Option (ARO)" )
	link1.send(ns)

	step (2, "We expect a neighboor advertisement with a valid Address Registration Option (ARO)" )
	t.start(TIMER1)

	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.addr ) /
		ICMPv6NAdv( opt = superop ( [
			SixARO(
				type = 33 , #FIXME: temp value, will be allocated
				Length = 2 ,
				Status = 0 ,
				Reserved = 0 ,
				eui = HOST1.eui64
				)
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1.3.10
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_10(NUT , TIMER1 , HOST1 , LBR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = NUT.lladdr ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)
	step (1, "We perform the common test setup 1.4b" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation" )
	link1.send(rs)

	step (2, "We expect a router advertisement with a valid Compress Option" )
	t.start(TIMER1)

	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.addr ) /
		ICMPv6RAdv( opt = superop ( [
			SixCO (
				type = 32 ,  #FIXME: temp value, will be allocated
				len = 3 ,
				clen = 64 ,
				rsv1 = 0,
				c = 1,
				cid = 1,
				rsv2 = 0,
				lt = 1,
				pf = PRFX1
				)
			] )
		)
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.3.11
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_3_11(NUT , TIMER1 , HOST1 , LBR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	rs = pack (
		IPv6( src = HOST1.lladdr , dst = NUT.lladdr ) /
		ICMPv6RSol( opt = [
			ICMPv6SLL( hw=HOST1.hwaddr )
			]
		)
	)
	step (1, "We perform the common test setup 1.4b" )
	CommonTestSetup_1_4( LBR1 , HOST1 , NUT, PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation" )
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)

	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.addr ) /
		ICMPv6RAdv( opt = superop ( [
			SixABRO (
				len = 3 ,
				lbr = LBR1.addr
				)
			] )
		)
	)
	set_verdict("pass")
################################################################################
# Main()
################################################################################

if __name__ == "__main__":
	print("Internal use only. Use testslr.py or testslbr.py")
	exit(1)
