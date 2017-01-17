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

from    ttproto.core.data import Value, BidictValueType
from    ttproto.core.lib.inet.meta import *
from    ttproto.core.lib.inet.basics import *
from    ttproto.core.lib.inet.ip import *
from    ttproto.core.lib.encap import encap_type_bidict
import ttproto.core.lib.ethernet

__all__ = [
    "IPv6",
    "IPV6_ALL_NODES",
    "IPV6_ALL_ROUTERS",
    "IPV6_UNSPECIFIED_ADDRESS",
]


class IPv6(
        metaclass=InetPacketClass,
        fields=[
            ("Version", "ver", UInt4, 6),
            ("TrafficClass", "tc", Hex(UInt8), 0),
            ("FlowLabel", "fl", Hex(UInt20), 0),
            ("PayloadLength", "len", UInt16, InetLength("Payload")),
            ("NextHeader", "nh", UInt8, InetType(ip_next_header_bidict, "Payload")),
            ("HopLimit", "hl", UInt8, 64),  # FIXME: should be 255 for NS messages
            ("SourceAddress", "src", IPv6Address, "::"),
            ("DestinationAddress", "dst", IPv6Address, "::"),
            ("Payload", "pl", Value, b"")
        ],
        descriptions={"nh": ip_next_header_descriptions},
):
    def describe(self, desc):
        desc.src = self["src"]
        desc.dst = self["dst"]
        if not self.describe_payload(desc):
            txt_desc = self.get_description("nh")
            desc.info = txt_desc if txt_desc else  "IPv6 nh: %d" % self["nh"]

        return True

    _build_message = InetPacketValue._build_message_ipv6_header


# tell the ethernet module that ether payload type 0x86dd should be mapped to the IPv6 class
ttproto.core.lib.ethernet.ethernet_type_bidict.update({
    0x86dd: IPv6,
})

# tell the encap module that encap  payload type 24, 28 and 30 should be mapped to the IPv6 class
ttproto.core.lib.encap.encap_type_bidict.update({
    24: IPv6,
    28: IPv6,
    30: IPv6
})

# map ip next header 41 to the IPv6 class (IPv6 over IPv6)
ip_next_header_bidict.update({
    41: IPv6,
})

#
# Well know Address
#

# TODO: implement a description dict of well known ipv6 addresses

# http://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xml
IPV6_ALL_NODES = IPv6Address("ff02::1")
IPV6_ALL_ROUTERS = IPv6Address("ff02::2")
IPV6_UNSPECIFIED_ADDRESS = IPv6Address("::")
