#!/usr/bin/env python3

from ..common import *


class TD_6LOWPAN_HC_03 (SixlowpanTestCase):
    """
====================        ===================================================
Identifier                  TD_6LoWPAN_HC_03
====================        ===================================================
Objective                   * Check that EUTs correctly handle compressed
                              6LoWPAN packets (EUI-64 link-local, hop limit=63)
Configuration               * Node - Node
References                  * RFC 6282 section 3
Pre-test conditions         * Header compression is enabled on both EUT1 and
                              EUT2
                            * EUT1 and EUT2 are configured to use EUI-64
                            * EUT1 and EUT2 are configured with a default hop
                              limit of 63
====================        ===================================================

=============== =========    ========    ======================================
Test Sequence   Step         Type        Description
=============== =========    ========    ======================================
.. ts           0            Stimulus    * EUT1 initiates an echo request to
                                           EUT2's link-local address
                                         * ICMP payload = 4 bytes, total IPv6
                                           size 52 bytes
                                         * Hop Limit is 63, no traffic class or
                                           flow label is being used

.. ts           1            Check       EUT1 sends a compressed 6LoWPAN packet
                                         containing the Echo Request message to
                                         EUT2

.. ts           2            Check       Dispatch value in 6LowPAN packet is
                                         "011TFxHL"

.. ts           3            Feature     In IP_HC, TF is 11 and the ecn, dscp
                                         and flow label fields are compressed
                                         away

.. ts           4            Feature     In IP_HC, HLIM (HL) is 00 and the hop
                                         limit field is carried in-line

.. ts           5            Feature     In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11

.. ts           6            Verify      EUT2 receives the Echo Request message
                                         from EUT1

.. ts           7            Check       EUT2 sends a compressed 6LoWPAN packet
                                         containing the Echo Reply message to
                                         EUT1

.. ts           8            Check       Dispatch value in 6LowPAN packet is
                                         "011TFxHL"

.. ts           9            Feature     In IP_HC, TF is 11 and the ecn, dscp
                                         and flow label fields are compressed
                                         away

.. ts           10           Feature     In IP_HC, HLIM (HL) is 00 and the hop
                                         limit field is carried in-line

.. ts           11           Feature     In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11

.. ts           12           Verify      EUT1 receives the Echo Reply message
                                         from EUT2

=============== =========    ========    ======================================

=============== ===============================================================
Notes           * The feature tests check that best compression is used (but
                  this is not a requirement for interoperability)
                * The Echo Reply message might use a different hop limit in
                  some implementations, then the HLIM value might also be
                  different.
=============== ===============================================================
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
    def get_nodes(cls) -> list_of(Node):
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
            Node('EUT1', ICMPv6EchoRequest()),
            Node('EUT2', ICMPv6EchoReply())
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
                        tc=0x00,
                        fl=0x00000,
                        hl=63,
                        pl=ICMPv6EchoRequest(
                            # pl=Length(bytes, 4)
                        )
                    )
                )
            )
        ]

    def run(self):

        # NOTE: Should we check the IP adresses to check that it is really the
        #       EUT1 and EUT2?

        # TS 1
        self.match('EUT1', SixLowpanIPHC(pl=IPv6(pl=ICMPv6EchoRequest())))

        # TS 2
        self.match('EUT1', SixLowpanIPHC(dp=0b011))

        # TS 3
        self.match('EUT1', SixLowpanIPHC(
            tf=0b11,
            iecn=Omit(),
            idscp=Omit(),
            ifl=Omit()
        ))

        # TS 4
        self.match('EUT1', SixLowpanIPHC(hl=0b00, ihl=UInt8()))

        # TS 5
        self.match('EUT1', SixLowpanIPHC(
            sac=False,
            sam=0b01,
            dac=False,
            dam=0b11
        ))

        # TS 6
        # NOTE: Only one sniff file so we can't check that the EUT2 didn't
        #       receive the echo request message

        self.next()

        # TS 7
        self.match('EUT2', SixLowpanIPHC(pl=IPv6(pl=ICMPv6EchoReply())))

        # TS 8
        self.match('EUT2', SixLowpanIPHC(dp=0b011))

        # TS 9
        self.match('EUT2', SixLowpanIPHC(
            tf=0b11,
            iecn=Omit(),
            idscp=Omit(),
            ifl=Omit()
        ))

        # TS 10
        self.match('EUT2', SixLowpanIPHC(hl=0b00, ihl=UInt8()))

        # TS 11
        self.match('EUT2', SixLowpanIPHC(
            sac=False,
            sam=0b11,
            dac=False,
            dam=0b11
        ))

        # TS 12
        # NOTE: Only one sniff file so we can't check that the EUT2 didn't
        #       receive the echo request message
