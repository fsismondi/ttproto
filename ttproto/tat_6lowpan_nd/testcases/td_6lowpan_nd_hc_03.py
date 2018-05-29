from ..common import *


class TD_6LOWPAN_ND_HC_03 (SixlowpanTestCase):
    """
---
TD_6LOWPAN_ND_HC_03:
    cfg: 6ln to 6lr
    not: Null
    obj: check that EUTs are able to perform the neighbor Discovery (16 bits to EUI-64 link-local addresses,
         hop limit=255)
    pre:
         - Header compression is enabled on both EUT1 and EUT2.
         - EUT1 is configured to use 16 bits addresses.
         - EUT2 is configured to use EUI-64 addresses.
         - EUT1 is configured as 6LN.
         - EUT2 is configured as 6LR.
    ref: RFC 6282 section 3; RFC 6775 5.6
    seq:
        -   s:
               - Initialize the network interface of the 6LR (EUT2)
               - Initialize the network interface of the 6LN (EUT1)
               - Hop Limit is 255, no traffic class or flow label is being used
        -   c: The 6LN sends à Neighbor Solicitation (NS) to all-nodes multicast address with SLLAO (EUI-64).
               Source = link-local based on EUI-64
        -   c: The 6LR (EUT2) receives the Neighbor Solicitation (NS) the 6LN (EUT1)
        -   f: "Hop Limit is 64 and source address begin by fe80::"
        -   f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are
                compressed away
        -   f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed
                away
        -   f: In IP_HC, SAC=0, SAM=01; DAC=0; DAM=01
        -   v: The 6LR (EUT2) receives the Neighbor Solicitation (NS) the 6LN (EUT1)
        -   c: The 6LR (EUT2) sends a unicast Neighbor Advertisement (NA) containing the ARO.
               Link local addresses are used.
        -   f: "Hop Limit is 1 and source address begin by fe80::"
        -   f: In IP_HC, TF is 11 and the ecn, dscp and flow label fields are
                compressed away
        -   f: In IP_HC, HLIM (HL) is 10 and the hop limit field is compressed
                away
        -   f: In IP_HC, SAC=0, SAM=11; DAC=0; DAM=01
        -   v: The 6LN (EUT1) receives the Neighbor Advertisement (NA) from the 6LR (EUT2)
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
                    # Length(IPv6, 35),
                    IPv6(
                        tc=0x00,
                        fl=0x00,
                        hl=255,
                        pl=ICMPv6NeighborSolicitation(
                            # pl=Length(bytes, 0)
                        )
                    )
                )
            )
        ]

    @classmethod
    @typecheck
    def get_nodes_identification_templates(cls) -> list_of(Node):
        """
        Get the nodes of this test case. This has to be be implemented into
        each test cases class.

        :return: The nodes of this TC
        :rtype: [Node]

        """
        return [
            Node('EUT1', ICMPv6NeighborSolicitation()),
            Node('EUT2', ICMPv6NeighborAdvertisement())
        ]

    def run(self):
        # NOTE: Should we check the IP adresses to check that it is really the
        #       EUT1 and EUT2?

        # TS 1
        self.match('EUT1', SixLowpanIPHC(pl=IPv6(pl=ICMPv6NeighborSolicitation())))

        # TS 2
        self.match('EUT1', SixLowpanIPHC(dp=0b011))

        # TS 3
        self.match('EUT1', SixLowpanIPHC(
            tf=0b11,
            iecn=0b00,
            sci=2,
            idscp=0b00,
            ifl=0x00
        ))
        self.match('EUT1', SixLowpanIPHC(pl=IPv6 (HopLimit = 255)))

        # TS 4
        self.match('EUT1', SixLowpanIPHC(hl=0b11, ihl=Omit()))

        # TS 5
        self.match('EUT1', SixLowpanIPHC(
            sac=False,
            sam=0b01,
            dac=False,
            dam=0b01
        ))

        # TS 6
        # NOTE: Only one sniff file so we can't check that the EUT2 didn't
        #       receive the echo request message

        self.next()

        # TS 7
        self.match('EUT2', SixLowpanIPHC(pl=IPv6(pl=ICMPv6NeighborAdvertisement())))

        # TS 8
        self.match('EUT2', SixLowpanIPHC(dp=0b011))

        # TS 9
        self.match('EUT2', SixLowpanIPHC(
            tf=0b11,
            iecn=0b00,
            sci=2,
            idscp=0b00,
            ifl=0x00
        ))

        # TS 10
        self.match('EUT2', SixLowpanIPHC(hl=0b11, ihl=Omit()))

        # TS 11
        self.match('EUT2', SixLowpanIPHC(
            sac=False,
            sam=0b11,
            dac=False,
            dam=0b01
        ))

        # TS 12
        # NOTE: Only one sniff file so we can't check that the EUT2 didn't
        #       receive the echo request message
