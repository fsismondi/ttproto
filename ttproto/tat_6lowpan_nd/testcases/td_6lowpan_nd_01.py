#!/usr/bin/env python3

from ..common import *

class TD_6LOWPAN_ND_01 (SixlowpanTestCase):

	"""
---
TD_6LoWPAN_ND_01:
    cfg: Host-6LR
    not:
    	- The Echo Reply message might use a different hop limit in some implementations,
    		then the HLIM value might also be different
    obj: Check that a host is able to register its global IPv6 address (EUI-64)
    pre:
        - Header compression is enabled on both Host and Router
        - Host is configured to use EUI-64 address
    ref: RFC 6775 10.2
    seq:
        -   s:
            - Initialize the network interface of the Host
        -   c: The Host sends a Router Solicitation to all-routers multicast address with SLLAO (EUI-64)
        -   c: Source = link local based on EUI-64
        -	v: The Router receives the Router Solicitation from the host
        -	c: The Router sends a unicast Router Advertisement containing PIO and optionally 6COs to the host
        -	c: Link local addresses are used
        -	c: The L bit is not set
        -	v: The host receives the Router Advertisement from the router
        -	c: The host configures its tentative global IPv6 address based on the PIO information in RA from the
        		Router (EUI-64)
        -	c: The host registers its tentative address by sending a unicast Neighbor Solicitation containing ARO
        		and SLLAO. Source = GP64
        -	v: The Router receives the Neighbor Solicitation from the host
        -	c: The Router sends a Neighbor Advertisement with Status set to 0 (Dest = GP64)
        -	v: The host updates the status of the tentative address
        -	s:
        	- The Router initiates an echo request to the Host's new global address, using its own global
        		address as the source
        	- ICMP payload = 4 bytes, total IPv6 size 52 bytes
        	- Hop Limit is 64, no traffic class or flow label is being used
        -	c: The Router sends a 6LoWPAN packet containing the Echo Request message to the Host
        -	c: "Dispatch value in 6LowPAN packet is \u201C011TFxHL\u201D"
        -	f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are compressed away
        -	f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed away
        -	v: The Host receives the Echo Request message from the Router
        -	c: The Host sends a 6LoWPAN packet containing the Echo Reply message to the Router
        -	c: "Dispatch value in 6LowPAN packet is \u201C011TFxHL\u201D"
        -	f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are compressed away
        -	f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed away
        -	v: The Router receives the Echo Reply message from the Host
    """

	@classmethod
	@typecheck
	def get_protocol(cls) -> is_protocol:
		"""
        Get the protocol corresponding to this test case. This has to be
        implemented into the protocol's common test case class.

        :return: The protocol on which this TC will occur
        :rtype: Value
        """
		return SixLowpanIPHC

	@classmethod
	@typecheck
	def get_nodes_identification_templates(cls) -> list_of(Node):
		"""
		Get the nodes of this test case. This has to be be implemented into
		each test cases class.

		:return: The nodes of this TC
		:rtype: [Node]

		.. note:: For CoAP it is simpler so we can define this function in this
				  class but for other protocols it can happend that we have to
				  define this inside each TC
		"""
		return [
			Node('HOST', ICMPv6RSol()),
			Node('ROUTER', ICMPv6RAdv())
		]

	@classmethod
	@typecheck
	def get_stimulis(cls) -> list_of(Value):
		"""
		Get the stimulis of this test case. This has to be be implemented into
		each test cases class.

		:return: The stimulis of this TC
		:rtype: [Value]

		.. warning::
			For the moment, we didn't manage to generate packets with the
			wanted size so we just don't take them into account
		"""
		return [
			SixLowpanIPHC(
				pl=All(
					# Length(IPv6, 52),
					IPv6(
						# tc=0x00,
						# fl=0x00000,
						# hl=64,
						pl=ICMPv6RSol(
							# pl=Length(bytes, 4)
						)
					)
				)
			),
			SixLowpanIPHC(
				pl=All(
					# Length(IPv6, 52),
					IPv6(
						tc=0x00,
						fl=0x00000,
						hl=64,
						pl=ICMPv6EchoRequest(
							# pl=Length(bytes, 4)
						)
					)
				)
			)
		]

	def run(self):

		# TS1
		self.match("HOST",  SixLowpanIPHC(pl=IPv6(pl=ICMPv6RSol())))

		# TS2
		self.next()

		# TS3
		self.match("ROUTER", SixLowpanIPHC(pl=IPv6(pl=ICMPv6RAdv())))

		# TS4
		self.next()

		# TS5

		# TS6
		self.match("HOST", SixLowpanIPHC(pl=IPv6(pl=ICMPv6NSol())))

		# TS7
		self.next()

		# TS8
		self.match("ROUTER", SixLowpanIPHC(pl=IPv6(pl=ICMPv6NAdv())))

		# TS9

		# TS10
		# Stimulus 2

		# TS 11
		self.match('ROUTER', SixLowpanIPHC(pl=IPv6(pl=ICMPv6EchoRequest())))

		# TS 12
		self.match('ROUTER', SixLowpanIPHC(dp=0b011))

		# TS 13
		self.match('ROUTER', SixLowpanIPHC(
			tf=0b11,
			iecn=Omit(),
			idscp=Omit(),
			ifl=Omit()
		))

		# TS 14
		self.match('ROUTER', SixLowpanIPHC(hl=0b10, ihl=Omit()))

		# TS 15
		# Verify

		self.next()

		# TS 16
		self.match('HOST', SixLowpanIPHC(pl=IPv6(pl=ICMPv6EchoReply())))

		# TS 17
		self.match('HOST', SixLowpanIPHC(dp=0b011))

		# TS 18
		self.match('HOST', SixLowpanIPHC(
			tf=0b11,
			iecn=Omit(),
			idscp=Omit(),
			ifl=Omit()
		))

		# TS 19
		self.match('HOST', SixLowpanIPHC(hl=0b10, ihl=Omit()))

		# TS 20
		# Verify


