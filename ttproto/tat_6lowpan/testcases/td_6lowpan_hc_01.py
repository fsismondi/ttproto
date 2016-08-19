from ..common import *


class TD_6LOWPAN_HC_01 (SixlowpanTestCase):
    """
---
TD_6LOWPAN_HC_01:
    cfg: Node-Node
    not:
        - The feature tests check that best compression is used (but this is
            not a requirement for interoperability)
        - The Echo Reply message might use a different hop limit in some
            implementations, then the HLIM value might also be different.
    obj: Check that EUTs correctly handle compressed 6LoWPAN packets (EUI-64
        link-local, hop limit=64)
    pre:
        - Header compression is enabled on both EUT1 and EUT2
        - EUT1 and EUT2 are configured to use EUI-64
        - EUT1 and EUT2 are configured with a default hop limit of 64
    ref: RFC 6282 section 3; RFC 6775 5.6
    seq:
        -   s:
            - EUT1 initiates an echo request to EUT2's link-local address
            - ICMP payload = 4 bytes, total IPv6 size 52 bytes
            - Hop Limit is 64, no traffic class or flow label is being used
        -   c: EUT1 sends a compressed 6LoWPAN packet containing the Echo
                Request message to EUT2
        -   c: "Dispatch value in 6LowPAN packet is \u201C011TFxHL\u201D"
        -   f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are
                compressed away
        -   f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed
                away
        -   f: In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11
        -   v: EUT2 receives the Echo Request message from EUT1
        -   c: EUT2 sends a compressed 6LoWPAN packet containing the Echo Reply
                message to EUT1
        -   c: "Dispatch value in 6LowPAN packet is \u201C011TFxHL\u201D"
        -   f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are
                compressed away
        -   f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed
                away
        -   f: In IP_HC, SAC=0, SAM=11; DAC=0; DAM=11
        -   v: EUT1 receives the Echo Reply message from EUT2
    """

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
    def get_nodes_identification_patterns(cls) -> list_of(Node):
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
