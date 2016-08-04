#!/usr/bin/env python3

from ..common import *


class TD_COAP_ANALYSIS_1 (CoAPAnalysis):
    """Identifier:
TD_COAP_CORE_01
Objective:
Perform GET transaction (CON mode)
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
                        hl=64,
                        pl=ICMPv6EchoRequest(
                            # pl=Length(bytes, 4)
                        )
                    )
                )
            )
        ]

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
        self.match('EUT1', SixLowpanIPHC(hl=0b10, ihl=Omit()))

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
        self.match('EUT2', SixLowpanIPHC(hl=0b10, ihl=Omit()))

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
