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
from .testsrouter import *
from . import implemR


################################################################################
# Test_LPND_1.4.1a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_4_1a(NUT , TIMER1 , HOST1 , LBR1 , PRFX1 , link1, action):

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

	step (1, "We perform the common test setup 1.2" )
	CommonTestSetup_1_2(LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation ")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)

	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6Adv( opt = superop ( [
			SixABRO ( lbr = LBR1.addr )
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1.4.1b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_4_1b(NUT , TIMER1 , HOST1 , LBR1 , LBR2 , PRFX1 , PRFX2 , link1, action):

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

	ra = pack (
		IPv6( src = LBR2.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
				SixABRO(lbr=LBR2.addr) ,
				SixPI( pf=PRFX2 , vlt = 120 )
			]
		)
	)

	step (1, "We perform the common test setup 1.2" )
	CommonTestSetup_1_2(LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router advertisement with an Authoritative Border Router Option")
	link1.send(ra)

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect 2 two router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)

	receive_unordered ( link1 , 
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 )
				] )
			)
		),
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR2.addr) ,
					SixPI( pf=PRFX2 , vlt = 120 )
				] )
			)
		)
	)
#	set_verdict("pass") handled by receive_unordered()

################################################################################
# Test_LPND_1.4.1c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_4_1c(NUT , TIMER1 , HOST1 , LBR1 , LBR2 , PRFX1 , link1, action):

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

	ra = pack (
		IPv6( src = LBR2.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
				SixABRO(lbr=LBR1.addr) ,
				SixPI( pf=PRFX1 , vlt = 120 )
			]
		)
	)

	step (1, "We perform the common test setup 1.2" )
	CommonTestSetup_1_2(LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router advertisement with an Authoritative Border Router Option")
	link1.send(ra)

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect two router advertisement with two identical Authoritative Border Router Option" )
	t.start(TIMER1)

	receive_unordered ( link1 , 
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 )
				] )
			)
		),
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 )
				] )
			)
		)
	)
#	set_verdict("pass") handled by receive_unordered()

################################################################################
# Test_LPND_1.4.1d
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_4_1d(NUT , TIMER1 , HOST1 , LBR1 , LBR2, PRFX1 , PRFX2 , link1, action):

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

	ra = pack (
		IPv6( src = LBR2.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
				SixABRO(lbr=LBR2.addr) ,
				SixPI( pf=PRFX2 , vlt = 120 ) ,
				SixCO( cid = 2 , c = 0 , clen = 64, pf = PRFX2)
			]
		)
	)

	step (1, "We perform the common test setup 1.2b" )
	CommonTestSetup_1_2b(LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router advertisement with an Authoritative Border Router Option")
	link1.send(ra)

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect 2 two router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)

	receive_unordered ( link1 , 
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 ) ,
					SixCO( cid = 1 , c = 1 , clen = 64, pf = PRFX1)
				] )
			)
		),
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR2.addr) ,
					SixPI( pf=PRFX2 , vlt = 120 ) ,
					SixCO( cid = 2 , c = 0 , clen = 64, pf = PRFX2)
				] )
			)
		)
	)
#	set_verdict("pass") handled by receive_unordered()

################################################################################
# Test_LPND_1.4.1e
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_4_1e(NUT , TIMER1 , HOST1 , LBR1 , LBR2 , PRFX1 , link1, action):

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

	ra = pack (
		IPv6( src = LBR2.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
				SixABRO(lbr=LBR1.addr) ,
				SixPI( pf=PRFX1 , vlt = 60 ) ,
				SixCO( cid = 1 ,clen = 64, pf = PRFX1)
			]
		)
	)

	step (1, "We perform the common test setup 1.2b" )
	CommonTestSetup_1_2b(LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router advertisement with an Authoritative Border Router Option")
	link1.send(ra)

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)

	receive_unordered ( link1 , 
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 ) ,
					SixCO( cid = 1 ,clen = 64, pf = PRFX1)
				] )
			)
		),
		(
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=LBR1.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 ) ,
					SixCO( cid = 1 ,clen = 64, pf = PRFX1)
				] )
			)
		)
	)
	set_verdict("pass")


################################################################################
# Main()
################################################################################

if __name__ == "__main__":
	with LoggerGroup ([ConsoleLogger(), HTMLLogger()]) as l:
		Logger.set_default (l)
#		ts = TestSession ([ init, Test_LPND_1_3_3c])
#		ts.set_config(SixLoWPAN_ND, SixLoWPAN_ND("router"))
#		ts.run()
		run_all_testcases({SixLoWPAN_ND: SixLoWPAN_ND("router")})
