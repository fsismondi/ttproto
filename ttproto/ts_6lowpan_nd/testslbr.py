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
from . import implem

#FIXME First, all tests in testslbr.py must pass
#from testsrouter import *


################################################################################
# Test_LPND_1.5.1a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_1a(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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

	step (1, "We perform the common test setup 1.3" )
	CommonTestSetup_1_3(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
				SixABRO(lbr=NUT.addr) ,
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1.5.1b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_1b(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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

	step (1, "We perform the common test setup 1.3" )
	CommonTestSetup_1_3(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "Preamble")
	action ("Reboot the NUT")

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
				SixPI( pf=PRFX1 , vlt = 60 )
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1.5.1c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_1c(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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

	step (1, "We perform the common test setup 1.3b" )
	CommonTestSetup_1_3b(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "Preamble")
	action ("Reboot the NUT")

	step (3, "We send a router solicitation")
	link1.send(rs)

	step (4, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
				SixPI( pf=PRFX1 , vlt = 60 ) ,
				SixCO( cid = 1 ,clen = 64, pf = PRFX1)
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1.5.1d
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_1d(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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

	version=0

	step (1, "We perform the common test setup 1.3" )
	CommonTestSetup_1_3(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=NUT.addr) ,
					SixPI( pf=PRFX1 , vlt = 60 )
				] )
			)
		)
		def _(value):
			version = value[IPv6][ICMPv6]["opt"][SixABRO]["ver"]
			set_verdict("pass")

	step (4, "NUT action")
	action (
"""Reconfigure the NUT:
	Change the prefix to %s
	Change the lifetime to 120
""" % PRFX2)

	step (2, "We send a router solicitation")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option and a Prefix Option corresponding to the new configured prefix and lifetime" )
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixABRO(lbr=NUT.addr) ,
					SixPI( pf=PRFX2, vlt = 120 )
				] )
			)
		)
		def _(value):
			if value[IPv6][ICMPv6]["opt"][SixABRO]["ver"] > version:
				set_verdict("pass")
			else:
				set_verdict("fail")


################################################################################
# Test_LPND_1.5.1e
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_1e(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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
	cid=0

	step (1, "We perform the common test setup 1.3" )
	CommonTestSetup_1_3b(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option" )
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixCO( c = 1 ,clen = 64, pf = PRFX1 , lt = 60 ) , 
				] )
			)
		)
		def _(value):
			cid = value[IPv6][ICMPv6]["opt"][SixCO]["ver"]
			set_verdict("pass")

	step (4, "NUT action")
	action (
"""Reconfigure the NUT:
	Change the prefix to %s
	Change the lifetime to 120
	Update the Context to
		- lifetime: 120
		- prefix: %s
		- compress: no
""" % (PRFX2, PRFX2))

	step (5, "We send a router solicitation")
	link1.send(rs)

	step (6, "We expect a router advertisement with a prefix option valid Authoritative Border Router Option" )
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
			ICMPv6RAdv( opt = superop ( [
					SixCO( c = 0 ,clen = 64, pf = PRFX2 , lt = 120 ) , 
				] )
			)
		)
		def _(value):
			if value[IPv6][ICMPv6]["opt"][SixCO]["cid"] > cid:
				set_verdict("pass")
			else:
				set_verdict("fail")

################################################################################
# Test_LPND_1.5.2a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_5_2a(NUT , TIMER1 , HOST1 , HOST2, PRFX1 , link1, action):

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

	step (1, "We perform the common test setup 1.3" )
	CommonTestSetup_1_3b(HOST1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We send a router solicitation")
	link1.send(rs)

	step (3, "We expect a router advertisement with a valid Authoritative Border Router Option , a prefix option for PRFX1 and a compress option for PRFX1 with the compress bit set to 1" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
				SixABRO(lbr=NUT.addr) ,
				SixPI( pf=PRFX1, vlt = 60 ) , 
				SixCO( c = 1 ,clen = 64, pf = PRFX1 , lt = 60 ) , 
			] )
		)
	)
	set_verdict("pass")
#

	step (4, "NUT action")
	action (
"""Reconfigure the NUT:
	Add a prefix: %s
		with the lifetime set to: 120
	Add a Context with
		- lifetime: 120
		- prefix: %s
		- compress: no
""" % (PRFX2, PRFX2))

	step (5, "We send a router solicitation")
	link1.send(rs)

	step (6, "We expect a router advertisement with two Context Option" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = HOST1.lladdr ) /
		ICMPv6RAdv( opt = superop ( [
				SixPI( pf=PRFX1, vlt = 60 ) , 
				SixPI( pf=PRFX2, vlt = 120 ) , 
				SixCO( c = 1 ,clen = 64, pf = PRFX1 , lt = 60 ) , 
				SixCO( c = 0 ,clen = 64, pf = PRFX2 , lt = 120 )
			] )
		)
	)
	set_verdict("pass")


################################################################################
# Main()
################################################################################

if __name__ == "__main__":
	with LoggerGroup ([ConsoleLogger(), HTMLLogger()]) as l:
		Logger.set_default (l)
#		ts = TestSession ([ init, Test_LPND_1_1_7a])
#		ts.set_config(SixLoWPAN_ND, SixLoWPAN_ND())
#		ts.run()
		run_all_testcases({SixLoWPAN_ND: SixLoWPAN_ND("borderRouter")})
