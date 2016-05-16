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
# Test_LPND_1_1_1a
###############################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_1a(NUT , TIMER1 , LBR1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router solicitation (RS) " )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) / 
		ICMPv6RSol( )
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1_1_1b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_1b(NUT , TIMER1 , LBR1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq = pack (
		IPv6 (src = LBR1.lladdr, dst = IPV6_ALL_NODES),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.1b"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "LBR-1 sends a ICMPv6 Echo Request to the  IPV6_ALL_NODES (", IPV6_ALL_NODES,") address")
	link1.send(ereq)

	step (3, "We expect an ICMPv6 Echo Reply")
	t.start(TIMER1)	

	link1.receive (IPv6()/ICMPv6EchoReply())
	set_verdict ("pass")

################################################################################
# Test_LPND_1_1_2a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_2a(NUT , TIMER1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect an ICMPv6 Router solicitation")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( dst = IPV6_ALL_ROUTERS ) /
			ICMPv6RSol( opt = superop ([
				ICMPv6SLL( hw=NUT.hwaddr ) 
				] )
			)
		)
		def _(value):
			if not value[IPv6] in IPv6(src = "::"):
				set_verdict ("pass")
			else:
				set_verdict ("fail")


################################################################################
# Test_LPND_1_1_2b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_2b(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr, hl = 255 ) ,
		ICMPv6RAdv( rlt = 30 , hp = 255 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr) , 
			SixPI( pf=PRFX1 , l = 0 ) , 
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect an ICMPv6 Router solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) 
			] )
		)
	)
	link1.send(ra)

	step (3, "We expect an ICMPv6 Neighboor solicitation and another ICMPv6 Router solicitation")
	t.start(30)
	link1.receive (
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			SixARO( )
			] )
		)
	)
	set_verdict ("pass")

	link1.receive (
		IPv6( src = NUT.lladdr ) /
		ICMPv6RSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) 
			] )
		)
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1_1_2c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_2c(NUT , TIMER1 , LBR1 , PRFX1, link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt =  [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI(pf=PRFX1,vlt = 30 , plt = 30 )

			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect an ICMPv6 Router solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) 
			] )
		)
	)
	link1.send(ra)

	step (3, "We expect an ICMPv6 Neighboor solicitation and another ICMPv6 Router solicitation")
	t.start(30)
	
	link1.receive (
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			SixARO()
			] )
		)
	)
	set_verdict ("pass")

	link1.receive (
		IPv6( src = NUT.lladdr , dst = LBR1.lladdr ) /
		ICMPv6RSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr )
			] )
		)
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1_1_2d (TODO/FIXME)
################################################################################
#TODO: verify timer value
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_2d(NUT , TIMER1 , TIMER2, LBR1 , PRFX1, link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect six (6) ICMPv6 Router solicitations")
	t.start(180) # 2x10 + 20 + 40 + max (60 , 80 ) + margin: 20 seconds
	timers = []

	for x in range(0,6):
		with alt: #FIXME: removable
			@link1.receive (
				IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
				ICMPv6RSol( opt = superop ( [
					ICMPv6SLL( hw=NUT.hwaddr ) 
					] )
				)
			)
			def _(value):
				timers.append( t._Timer__clock.time())

	margin = 1

	for x in range(1,6): # we ignore the day of the first RS
		delay = timers[x] - timers[x-1]
		step(2,"RS #"+repr(x+1)+" received after "+repr(delay) + " seconds after RS#"+repr(x))

		if x == 1 or x == 2:
			if delay >= 10 - margin :
				set_verdict("pass")
			else:
				set_verdict("fail")				
		elif x == 3:
			if delay >= 20 - margin:
				set_verdict("pass")
			else:
				set_verdict("fail")
		elif x == 4:
			if delay >= 40 - margin:
				set_verdict("pass")
			else:
				set_verdict("fail")
		elif x == 5:
			if delay >= 60 - margin: # 2x40 = 80. "However, it is useful to have a maximum retransmission timer of 60 seconds"
				set_verdict("pass")
			else:
				set_verdict("fail")	

	step (3, "We send an ICMPv6 Router Advertisement and don't except any Router Solicitation")
	link1.send(ra)
	t2.start(TIMER2)
	with alt:
		@link1.receive (
			IPv6( src = NUT.lladdr ) /
			ICMPv6RSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) 
				] )
			)
		)
		def _():
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1_1_3a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_3a(NUT , TIMER1 , LBR1 , link1, action, PRFX1):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , l=0 )
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	t.stop()

	step (3, "We expect a Neighbour Solicitation with an Address Registration Option")
	t.start(TIMER1)

	link1.receive (
		IPv6( src = NUT.addr , dst=LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			SixARO( eui = NUT.eui64 )
			] )
		)
	)
	set_verdict ("pass")


################################################################################
# Test_LPND_1_1_3b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_3b(NUT , TIMER1 , LBR1 , link1, action, PRFX1,TIMER2):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , l=1 )
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	t.stop()

	step (3, "We expect that the NUT don't send any Neighbour Solicitation")
	t2.start(TIMER2)
	with alt:
		@link1.receive (
			IPv6( src = NUT.addr , dst=LBR1.lladdr ) /
			ICMPv6NSol( )
		)
		def _():
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1_1_3c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_3c(NUT , TIMER1 , LBR1 , link1, action, PRFX1, PRFX2):


	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 ) ,
			SixPI( pf=PRFX2 ) ,
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	t.stop()

	step (3, "We expect two Neighbour Solicitation with an Address Registration Option to sends two Neighbour Advertisement")
	t.start(TIMER1)

	addr1 = IPv6Prefix(PRFX1).make_address(Eui64Address(NUT.eui64))
	addr2 = IPv6Prefix(PRFX2).make_address(Eui64Address(NUT.eui64))

	received_neighboursolicitions = receive_unordered (
		link1 , 
		IPv6( src =  addr1 , dst=LBR1.lladdr ) / ICMPv6NSol( opt = superop ( [ SixARO( eui = NUT.eui64	) ] ) ) ,
		IPv6( src =  addr2 , dst=LBR1.lladdr ) / ICMPv6NSol( opt = superop ( [ SixARO( eui = NUT.eui64	) ] ) ) ,
		)
	set_verdict ("pass")
	for ns in received_neighboursolicitions:
		na = pack (
			IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
			ICMPv6NAdv( opt = [
				SixARO( lt = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 , 
					eui= ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
				]
			)
		)
		link1.send(na)

	step (4, "We sends two ICMPv6 Echo Request and Expect two ICMPv6 Echo Reply")
	t.start(TIMER1)
	for addr in [ addr1 , addr2 ]:
		ereq = pack (
			IPv6 (src = LBR1.addr, dst = addr),
			ICMPv6EchoRequest(),
			"6lowpan-nd-1.1.3c-"+str(addr)
		)
		link1.send(ereq)

	receive_unordered (
		link1 , 
		IPv6( src =  addr1 , dst=LBR1.addr ) / ICMPv6EchoReply(),
		IPv6( src =  addr2 , dst=LBR1.addr ) / ICMPv6EchoReply(),
		)

################################################################################
# Test_LPND_1_1_4a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_4a(NUT , TIMER1 , TIMER2, LBR1 , link1, action, PRFX1):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 ,  m=0,  opt = [ 
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send an ICMPv6 Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighbour solicitation")
	t.start(TIMER1)
	link1.receive (
		IPv6( src=NUT.addr , dst=LBR1.lladdr) /
		ICMPv6NSol( opt = superop ( [
			SixARO( eui = NUT.eui64 ) ,
			ICMPv6SLL( hw=NUT.hwaddr )
			] )
		)
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1_1_5a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_5a(NUT , TIMER1, TIMER2 , LBR1 , PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )


	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5a"
	)

	step (1, "We perform the common test setup 1.1 with a router lifetime set to 30" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 , routerlt = 30 )

	step (2, "We expect a Router Solicitation Before 30 seconds" )
	t.start(30)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = LBR1.lladdr ) /
		ICMPv6RSol( )
	)
	set_verdict ("pass")
	t.stop()

	step (3, "We wait for 30 seconds..." )
	t.start (30)
	t.timeout()

	step (4, "We sends an Echo Request and don't expect any answer" )
	t2.start(TIMER2)
	link1.send(ereq)

	with alt:
		@link1.receive (
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		)
		def _():
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1_1_5b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_5b(NUT , TIMER1 , TIMER2 , LBR1 , PRFX1, link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5b"
	)

	step (1, "We perform the common test setup 1.1 with a prefix lifetime set to 30" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 , prefixlt = 30 )

	step (2, "We expect a Router Solicitation Before 30 seconds" )
	t.start(30)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = LBR1.lladdr ) /
		ICMPv6RSol( )
	)
	set_verdict ("pass")
	t.stop()

	step (3, "We wait for 30 seconds..." )
	t.start (30)
	t.timeout()

	step (4, "We sends an Echo Request and don't expect any answer" )
	link1.send(ereq)
	t2.start(TIMER2)
	with alt:
		@link1.receive (
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		)
		def _():
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1_1_5c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_5c(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq1 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5c-1"
	)
	ereq2 = pack (
		SixLowpanIPHC() ,
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5c-2"
	)
	ereq3 = pack (
		SixLowpanIPHC() ,
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5c-3"
	)


	step (1, "We perform the common test setup 1.1b with a context lifetime set to 30" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1 , contextlt = 30 )

	step (2, "We expect a Router Solicitation Before 30 seconds" )
	t.start(30)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = LBR1.lladdr ) /
		ICMPv6RSol( )
	)
	t.stop()

	step (3, "We wait for 30 seconds..." )
	t.start (30)
	t.timeout()

	step (4, "We sends two ICMPv6 Echo Request (One compressed, one not compressed). We expect two uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq1)
	link1.send(ereq2)
	t.start(TIMER1)

	receive_unordered ( link1 ,
		(
			SixLowpanIPv6() /
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		),
		(
			SixLowpanIPHC() /
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		)
	)

	step (5, "We wait for 60 seconds..." )
	t.start(60)
	t.timeout()

	step (6, "We sends a compressed ICMPv6 Echo Request. We expect a uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq3)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPv6() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1_1_5d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_5d(NUT , TIMER1 , LBR1 , PRFX1 , SLEEP1, link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , vlt = 60 ) ,
			SixCO( c=0 , clen=64, pf=PRFX1 , lt=60)
			]
		)
	)

	ereq1 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5d-1"
	)
	ereq2 = pack (
		SixLowpanIPHC() ,
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5d-2"
	)
	ereq3 = pack (
		SixLowpanIPHC() ,
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.5d-3"
	)

	step (1, "We perform the common test setup 1.1b with a context lifetime set to 30" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1 , contextlt = 30 )

	step (2, "We sends a Router Adverstisement with the Compress (C) bit set to 0" )
	link1.send(ra)

	step (3, "We sends two ICMPv6 Echo Request (One compressed, one not compressed). We expect two uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq1)
	link1.send(ereq2)
	t.start(TIMER1)

	receive_unordered ( link1 ,
		(
			SixLowpanIPv6() /
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		),
		(
			SixLowpanIPv6() /
			IPv6( src=NUT.addr ) /
			ICMPv6ERep()
		)
	)

	step (4, "We wait for 60 seconds..." )
	t.start (60)
	t.timeout()

	step (5, "We sends a compressed ICMPv6 Echo Request. We expect a uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq3)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPv6() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")


################################################################################
# Test_LPND_1_1_5e
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_5e(NUT , TIMER1 , PRFX1 , LBR1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 , routerlt = 30 )
	
	step (2, "We wait for 30 seconds")
	t.start(30)
	t.stop()

	step (2, "We expect an unicast router solicitation and a multicast one")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = LBR1.lladdr ) /
		ICMPv6RSol( )
	)
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol()
		)

	set_verdict ("pass")


################################################################################
# Test_LPND_1_1_6a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6a(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ra2 = pack (
		IPv6( src = LR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send two (2) Router advertisements" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	link1.send(ra)
	link1.send(ra2)

	step (3, "We expect two (2) Neighbor solicitation")
	t.start(TIMER1)
	receive_unordered ( link1 ,
		(
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( eui = NUT.eui64 )
				] )
			)
		),
		(
			IPv6( src = NUT.addr , dst = LR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( eui = NUT.eui64  )
				] )
			)
		) 
	)
	set_verdict ("pass")	


################################################################################
# Test_LPND_1_1_6b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6b(NUT , TIMER1 , LBR1 , PRFX1, SLEEP1, link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , vlt = 60 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.6b"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol(opt = superop ( [
				SixARO( )
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0,
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (3, "We sends an ICMPv6 Echo Request and expect for an Answer")
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive ( IPv6()/ICMPv6EchoReply() )
	set_verdict ("pass")


################################################################################
# Test_LPND_1_1_6c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6c(NUT , TIMER1 , LBR1 , link1, action, PRFX1):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt =  [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , vlt = 60 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.6c"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 1 , 
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (3, "We sends an ICMPv6 Echo Request and don't expect for an answer")
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1_1_6d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6d(NUT , TIMER1 , LBR1 , LR1, link1, action, PRFX1):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ra2 = pack (
		IPv6( src = LR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv(opt = [
			ICMPv6SLL( hw=LR1.hwaddr ) ,
			SixPI( pf=PRFX1  )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.6d"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send two (2) Router advertisements" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	link1.send(ra2)

	step (3, "We expect two (2) Neighboor Solicitations to send two (2) Neighboor Advertisements " )
	received_neighboursolicitions = receive_unordered ( link1 ,
		( 
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol(opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		),
		( 
			IPv6( src = NUT.addr , dst = LR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)
	)
	ns = received_neighboursolicitions.pop()
	ns2 = received_neighboursolicitions.pop()

	na = pack (
		IPv6( src = ns[IPv6]["dst"] , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0,
				eui= ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	na2 = pack (
		IPv6( src = ns2[IPv6]["dst"] , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = ns2[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 1,
					eui= ns2[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	link1.send(na)
	link1.send(na2)

	step (4, "We expect a Neighboor Solicitations" )
	t.start(TIMER1)
	link1.receive ( 
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO( lt = 0 )
			] )
		)
	)

	step (5, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1_1_6e
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6e(NUT , TIMER1 , LBR1 , link1, action, PRFX1):
	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( rlt = 60 , opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 , vlt = 60 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.6e"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 2 ,
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (4, "We expect a multicast Router Solicitation")
	t.start(TIMER1)
	link1.receive ( 
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			] )
		)
	)

	step (5, "We sends an ICMPv6 Echo Request and don't expect any answer")
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)

	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1_1_6f
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6f(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ra2 = pack (
		IPv6( src = LR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv(opt = [
			ICMPv6SLL( hw=LR1.hwaddr ) ,
			SixPI( pf=PRFX1  )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.6f"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send two (2) Router advertisements" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	link1.send(ra2)
		
	step (3, "We expect two (2) Neighboor Solicitations to send two (2) Neighboor Advertisements " )
	received_neighboursolicitions = receive_unordered ( link1 ,
		( 
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol(opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		),
		( 
			IPv6( src = NUT.addr , dst = LR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)	
	)

	ns = received_neighboursolicitions.pop()
	ns2 = received_neighboursolicitions.pop()

	na = pack (
		IPv6( src = ns[IPv6]["dst"] , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 ,
				eui= ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	na2 = pack (
		IPv6( src = ns2[IPv6]["dst"] , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = ns2[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 2 ,
				eui= ns2[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	link1.send(na)
	link1.send(na2)

	step (4, "We sends an ICMPv6 Echo Request and expect an answer via LR-1")
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = LBR1.addr )	/ ICMPv6EchoReply() , dst = LR1.hwaddr )
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.6g
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_6g(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	step (2, "NUT action")
	action ("Press enter, then shutdown the NUT")

	step (3, "We except a Neighboor Solicitation" )
	t.start(TIMER1)
	link1.receive ( 
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO( lt = 0 )
			] )
		)
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.7a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_7a(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):
	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.7a"
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 , len = 1,
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (4, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1.1.7b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_7b(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):
	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.7b"
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 0 , eui = '0123456789012345' )
					]
				)
			)
			link1.send(na)

	step (4, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.1.7c
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_7c(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1)
			]
		)
	)



	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.7c"
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"], st = 0 ,
						eui = value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (4, "We sends an ICMPv6 Echo Request and expect an answer" )
	link1.send(ereq)
	t.start(TIMER1)

	link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.8a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_8a(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.8a"
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (3, "We expect a Neighboor Solicitation and don't send any Neighboor Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO()
			] )
		)
	)

	step (4, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.1.8b
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_8b(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.8b"
	)
	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router Advertisement")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)

	step (2, "We expect a Neighboor Solicitation to send a Neighboor Advertisement")
	t.start(TIMER1)
	with alt:	#FIXME: removable
		@link1.receive (
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO()
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv( opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 80 ,
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (5, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1.1.8c 
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_8c(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ra2 = pack (
		IPv6( src = LR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv(opt = [
			ICMPv6SLL( hw=LR1.hwaddr ) ,
			SixPI( pf=PRFX1  )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.8c"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send two (2) Router advertisements" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
	link1.send(ra2)
		
	step (3, "We expect two (2) Neighboor Solicitations to send two (2) Neighboor Advertisements" )
	received_neighboursolicitions = receive_unordered( link1 ,
		( 
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol(opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		),
		( 
			IPv6( src = NUT.addr , dst = LR1.lladdr ) /
			ICMPv6NSol( opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)
	)


	ns = received_neighboursolicitions.pop()
	ns2 = received_neighboursolicitions.pop()

	if ns[IPv6]["dst"] == IPv6Address(LBR1.lladdr):
		lt = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"]
		l2 = ns2[IPv6][ICMPv6]["opt"][SixARO]["lt"]
	elif ns2[IPv6]["dst"] == IPv6Address(LBR1.lladdr):
		lt = ns2[IPv6][ICMPv6]["opt"][SixARO]["lt"]
		lt2 = ns[IPv6][ICMPv6]["opt"][SixARO]["lt"]	
	else:
		set_verdict("Error")

	na = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = lt , st = 0 , eui = ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	na2 = pack (
		IPv6( src = LR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6NAdv(opt = [
			SixARO( lt = lt2 , st = 1 , eui = ns[IPv6][ICMPv6]["opt"][SixARO]["eui"])
			]
		)
	)

	link1.send(na)
	link1.send(na2)
	step (4, "We expect a Neighboor Solicitations" )
	t.start(TIMER1)
	link1.receive ( 
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO( lt = 0 )
			] )
		)
	)

	step (5, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")

################################################################################
# Test_LPND_1.1.8d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_8d(NUT , TIMER1 , LBR1 , LR1 , PRFX1 , link1, action):

	t = Timer()
	t2 = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 )
			]
		)
	)

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.8d"
	)

	step (1, "Preamble")
	action ("Initialize the network of the NUT")

	step (2, "We expect a Router Solicitation to send a Router advertisement" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)
	link1.send(ra)
			
	step (3, "We expect a Neighboor Solicitations to send a Neighboor Advertisement" )
	with alt:	#FIXME: removable
		@link1.receive ( 
			IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
			ICMPv6NSol(opt = superop ( [
				ICMPv6SLL( hw=NUT.hwaddr ) ,
				SixARO( )
				] )
			)
		)
		def _(value):
			na = pack (
				IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
				ICMPv6NAdv(opt = [
					SixARO( lt = value[IPv6][ICMPv6]["opt"][SixARO]["lt"] , st = 2 ,
						eui= value[IPv6][ICMPv6]["opt"][SixARO]["eui"])
					]
				)
			)
			link1.send(na)

	step (4, "We expect a Router Solicitation" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	step (5, "We sends an ICMPv6 Echo Request and don't expect any answer" )
	link1.send(ereq)
	t.stop()
	t2.start(TIMER1)
	with alt:
		@link1.receive ( IPv6( src=NUT.addr , dst = LBR1.addr )/ICMPv6EchoReply() )
		def _( ):
			set_verdict ("fail")

		@t2.timeout ()
		def _():
			set_verdict ("pass")


################################################################################
# Test_LPND_1.1.9a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_9a(NUT , TIMER1 , LBR1 , LR1, HOST2 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	ereq1 = pack (
		IPv6 (src = LBR1.lladdr, dst = NUT.lladdr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9a-LBR1"
	)
	ereq2 = pack (
		IPv6 (src = LR1.lladdr, dst = NUT.lladdr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9a-LR1"
	)
	ereq3 = pack (
		IPv6 (src = HOST2.lladdr, dst = NUT.lladdr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9a-HOST2"
	)

	step (2, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq1)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.lladdr , dst = LBR1.lladdr ) / ICMPv6EchoReply() , dst=LBR1.hwaddr )
	set_verdict ("pass")

	step (3, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq2)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.lladdr , dst = LR1.lladdr ) / ICMPv6EchoReply() , dst=LR1.hwaddr )
	set_verdict ("pass")

	step (4, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq3)
	t.start(TIMER1)
	link1.receive ( IPv6( src=NUT.lladdr , dst = HOST2.lladdr ) / ICMPv6EchoReply() , dst=HOST2.hwaddr )

	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.9b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_9b(NUT , TIMER1 , LBR1 , PRFX1 , PRFX2 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	ereq = pack (
		IPv6 (src = IPv6Address(PRFX2.replace("::","") + "::1"), dst = NUT.lladdr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9b"
	)

	step (2, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.lladdr , dst = IPv6Address(PRFX2.replace("::","") + "::1") ) / ICMPv6EchoReply() , dst=LBR1.hwaddr	)

	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.9c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_9c(NUT , TIMER1 , LBR1 , LR1, PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	ereq1 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9c-LBR1"
	)
	ereq2 = pack (
		IPv6 (src = LR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.9c-LR1"
	)

	step (2, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq1)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = LBR1.addr ) / ICMPv6EchoReply() , dst=LBR1.hwaddr )

	set_verdict ("pass")

	step (3, "We sends an ICMPv6 Echo Request" )
	link1.send(ereq2)
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = LR1.addr ) /	ICMPv6EchoReply() , dst=LBR1.hwaddr )

	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.9d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_9d(NUT , TIMER1 , LBR1, PRFX1 , link1, action):
#FIXME: allow any pl
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	step (2, "NUT action")
	action ("Order the NUT to Send an ICMPv6 Echo Request to %s" % IPV6_ALL_NODES )
	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = IPV6_ALL_NODES ) / ICMPv6EchoRequest() , dst=LBR1.hwaddr )

	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.9e
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_9e(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):
#FIXME: allow any pl
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	addr = IPv6Address( str(PRFX1).replace("::","") + ":FDFF:FFFF:FFFF:FF2A" )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	step (2, "NUT action")
	action ("Order the NUT to Send an ICMPv6 Echo Request to %s" % addr)

	t.start(TIMER1)
	link1.receive (	IPv6( src=NUT.addr , dst = addr) / ICMPv6EchoRequest() , dst=LBR1.hwaddr )

	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.10a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_10a(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 )

	step (2, "NUT action")
	action ("Order the NUT to sleep for 60 seconds")

	step (3, "Wait 60 seconds")
	t.start (60)
	t.timeout()

	step (4, "We expect the NUT to send an ICMPv6 Neighboor solicitation")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.addr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO()
			] )
		)
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.10b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_10b(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1( LBR1 , NUT , PRFX1 , TIMER1, link1 , routerlt=60 , prefixlt=120 )

	step (2, "NUT action")
	action ("Order the NUT to sleep for 60 seconds")

	step (3, "Wait 60 seconds")
	t.start (60)
	t.timeout()

	step (4, "We expect the NUT to send an ICMPv6 Router solicitation")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.addr) /
		ICMPv6RSol( )
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.10c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_10c(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1b" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1 , routerlt=120 , prefixlt=60 )

	step (2, "NUT action")
	action ("Order the NUT to sleep for 60 seconds")

	step (3, "Wait 60 seconds")
	t.start (60)
	t.timeout()

	step (4, "We expect the NUT to send an ICMPv6 Router solicitation")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.addr) /
		ICMPv6RSol( )
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.10d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_10d(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	step (1, "We perform the common test setup 1.1" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1 , routerlt=120 , prefixlt=120 , contextlt=60 )

	step (2, "NUT action")
	action ("Order the NUT to sleep for 60 seconds")

	step (3, "Wait 60 seconds")
	t.start (60)
	t.timeout()

	step (4, "We expect the NUT to send an ICMPv6 Router solicitation")
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.addr) /
		ICMPv6RSol( )
	)
	set_verdict ("pass")

################################################################################
# Test_LPND_1.1.11a
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_11a(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq1 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11a-1"
	)

	ereq2 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11a-b"
	)

	step (1, "We perform the common test setup 1.1b" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We sends an ICMPv6 Echo Request. We expect a compressed ICMPv6 Echo Reply" )
	link1.send(ereq1)
	t.start(TIMER1)

	link1.receive (
		SixLowpanIPHC() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")

	step (3, "We wait for 60 seconds..." )
	t.start (60)
	t.timeout()
	step (4, "We sends an ICMPv6 Echo Request. We expect a uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq2)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPv6() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.1.11b
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_11b(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11b"
	)

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 ) ,
			SixCO( c=1 , clen=64, pf=PRFX1 , lt=120)
			]
		)
	)


	step (1, "We perform the common test setup 1.1b" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We sends an ICMPv6 Echo Request. We expect a compressed ICMPv6 Echo Reply" )
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPHC() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")

	step (3, "LBR1 sends a router advertisement")
	link1.send(ra)

	step (4, "We wait for 60 seconds..." )
	t.start (60)
	t.timeout()

	step (5, "We sends an ICMPv6 Echo Request. We expect a compressed ICMPv6 Echo Reply" )
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPHC() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.1.11c
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_11c(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11c"
	)

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 ) ,
			SixCO( c=1 , clen=64, pf=PRFX1 , lt=0)
			]
		)
	)

	step (1, "We perform the common test setup 1.1b" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "We sends an ICMPv6 Echo Request. We expect a compressed ICMPv6 Echo Reply" )
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPHC() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)

	step (3, "LBR1 sends a router advertisement")
	link1.send(ra)

	step (4, "We sends an ICMPv6 Echo Request. We expect an uncompressed ICMPv6 Echo Reply" )
	link1.send(ereq)
	t.start(TIMER1)
	link1.receive (
		SixLowpanIPv6() /
		IPv6( src=NUT.addr ) /
		ICMPv6ERep()
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.1.11d
################################################################################

@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_11d(NUT , TIMER1 , LBR1 , LBR2 , PRFX1 , link1, action):
	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ereq1 = pack (
		IPv6 (src = LBR1.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11d"
	)
	ereq2 = pack (
		IPv6 (src = LBR2.addr, dst = NUT.addr ),
		ICMPv6EchoRequest(),
		"6lowpan-nd-1.1.11d"
	)

	ra = pack (
		IPv6( src = LBR2.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR2.hwaddr ) ,
			SixPI( pf=PRFX1 ) ,
			SixCO( c=2 , clen=64, pf=PRFX1 , lt=60)
			]
		)
	)

	step (1, "We perform the common test setup 1.1b" )
	CommonTestSetup_1_1b( LBR1 , NUT , PRFX1 , TIMER1, link1)

	step (2, "LBR1 sends a router advertisement")
	link1.send(ra)

	step (3, "We sends an two ICMPv6 Echo Request. We expect two compressed ICMPv6 Echo Reply" )
	link1.send(ereq1)
	link1.send(ereq2)
	t.start(TIMER1)
	receive_unordered ( link1 ,
		(
			SixLowpanIPHC( dci=1 , dac = 1 ) /
			IPv6( src=NUT.addr , dst=LBR1.addr ) /
			ICMPv6ERep()
		),
		(
			SixLowpanIPHC( dci=2  , dac = 1 ) / #FIXME: verify
			IPv6( src=NUT.addr , dst=LBR2.addr ) /
			ICMPv6ERep()
		)
	)
	set_verdict("pass")

################################################################################
# Test_LPND_1.1.12a
################################################################################
@testcase(SixLoWPAN_ND)
def Test_LPND_1_1_12a(NUT , TIMER1 , LBR1 , PRFX1 , link1, action):

	t = Timer()

	unexpected_packets.activate( link1 )
	timeout.activate( t )

	ra = pack (
		IPv6( src = LBR1.lladdr , dst = NUT.lladdr ) ,
		ICMPv6RAdv( opt = [
			ICMPv6SLL( hw=LBR1.hwaddr ) ,
			SixPI( pf=PRFX1 ) ,
			]
		)
	)

	step (1, "We wait for a Router Solicitation to Send a Router Advertisement" )
	t.start(TIMER1)
	link1.receive (
		IPv6( src = NUT.lladdr , dst = IPV6_ALL_ROUTERS ) /
		ICMPv6RSol( )
	)

	link1.send(ra)
	t.start(TIMER1)

	step (1, "We except a Neighboor solicitation with well formated Address registration option" )
	link1.receive (
		IPv6( src = NUT.addr , dst = LBR1.lladdr ) /
		ICMPv6NSol( opt = superop ( [
			ICMPv6SLL( hw=NUT.hwaddr ) ,
			SixARO(
				type = 31, #TODO: TB1, will be allocated ,
				#length = 2 , not present in the sixARO description
				st = 0 ,
				rsv = 0 ,
				eui = NUT.eui64
				)
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
#		ts = TestSession ([ init, Test_LPND_1_1_8c ])
#		ts.set_config(SixLoWPAN_ND, SixLoWPAN_ND("host"))
#		ts.run()
		run_all_testcases({SixLoWPAN_ND: SixLoWPAN_ND("host")})
