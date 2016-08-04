#!/usr/bin/env python3

from ..common import *

class TD_6LOWPAN_HC_01 (SixlowpanTestCase):

    """
====================        ===========================================================================================
Identifier                  TD_6LoWPAN_HC_01
====================        ===========================================================================================
Objective                   * Check that EUTs correctly handle compressed 6LoWPAN packets (EUI-64 linklocal, hop limit=64)
Configuration               * Node - Node
References                  * RFC 6282 section 3
Pre-test conditions         * Header compression is enabled on both EUT1 and EUT2
                            * EUT1 and EUT2 are configured to use EUI-64
                            * EUT1 and EUT2 are configured with a default hop limit of 64
====================        ===========================================================================================

=============== =========    ========    ===================================================================================
Test Sequence   Step         Type        Description
=============== =========    ========    ===================================================================================
.. ts           0            Stimulus    * EUT1 initiates an echo request to EUT2's link-local address
                                         * ICMP payload = 4 bytes, total IPv6 size 52 bytes
                                         * Hop Limit is 64, no traffic class or flow label is being used

.. ts           1            Check       EUT1 sends a compressed 6LoWPAN packet containing the Echo Request message to EUT2

.. ts           2            Check       Dispatch value in 6LowPAN packet is "011TFxHL"

.. ts           3            Feature     In IP_HC, TF is 11 and the ecn, dscp and flow label fields are compressed away

.. ts           4            Feature     In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed away

.. ts           5            Feature     In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11

.. ts           6            Verify      EUT2 receives the Echo Request message from EUT1

.. ts           7            Check       EUT2 sends a compressed 6LoWPAN packet containing the Echo Reply message to EUT1

.. ts           8            Check       Dispatch value in 6LowPAN packet is "011TFxHL"

.. ts           9            Feature     In IP_HC, TF is 11 and the ecn, dscp and flow label fields are compressed away

.. ts           10           Feature     In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed away

.. ts           11           Feature     In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11

.. ts           12           Verify      EUT1 receives the Echo Reply message from EUT2

=============== =========    ========    ===================================================================================

=============== ============================================================================================================
Notes           * The feature tests check that best compression is used (but this is not a requirement for interoperability)
                * The Echo Reply message might use a different hop limit in some implementations, then the HLIM value might also be different.
=============== ============================================================================================================
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
            Node('EUT1', ICMPv6(type=128)),
            Node('EUT2', ICMPv6(type=129))
        ]

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        return [ICMPv6(type=128)]

    def run(self):
        self.match("EUT1", ICMPv6(type=128))

        self.next()

        self.match("EUT2", SixLowpan(ICMPv6(type=129)))