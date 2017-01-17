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
from    ttproto.core.data import Value
from    ttproto.core.lib.inet.meta import *
from    ttproto.core.lib.inet.basics import *
from    ttproto.core.lib.inet.ip import *
from    ttproto.core.lib.encap import encap_type_bidict
import ttproto.core.lib.ethernet

__all__ = [
    "IPv4",
]


class _IPv4HeaderLength(InetLength):
    def __init__(self):
        super().__init__("Options", 4)

    def post_decode(self, ctx, value):
        super().post_decode(ctx, value - 5)

    def compute(self, seq, values_bins):
        return super().compute(seq, values_bins) + 5


class IPv4(
        metaclass=InetPacketClass,
        fields=[
            ("Version", "ver", UInt4, 4),
            ("HeaderLength", "ihl", UInt4, _IPv4HeaderLength()),
            ("TypeOfService", "tos", Hex(UInt8), 0),
            ("TotalLength", "len", UInt16, InetLength()),
            ("Identification", "id", Hex(UInt16), 0),
            ("Reserved", "rsv", bool, 0),
            ("DontFragment", "df", bool, 0),
            ("MoreFragments", "mf", bool, 0),
            ("FragmentOffset", "off", UInt13, 0),
            ("TimeToLive", "ttl", UInt8, 64),
            ("Protocol", "pro", UInt8, InetType(ip_next_header_bidict, "Payload")),
            ("HeaderChecksum", "chk", Hex(UInt16), 0),  # TODO: compute the checksum
            ("SourceAddress", "src", IPv4Address, "0.0.0.0"),
            ("DestinationAddress", "dst", IPv4Address, "0.0.0.0"),
            ("Options", "opt", bytes, b""),
            ("Payload", "pl", Value, b""),
        ],
        descriptions={"pro": ip_next_header_descriptions},
):
    def describe(self, desc):
        desc.src = self["src"]
        desc.dst = self["dst"]
        if not self.describe_payload(desc):
            txt_desc = self.get_description("pro")
            desc.info = txt_desc if txt_desc else  "IPv4 nh: %d" % self["nh"]

        return True

    _build_message = InetPacketValue._build_message_ipv6_header


# tell the ethernet module that ether payload type 0x86dd should be mapped to the IPv4 class
ttproto.core.lib.ethernet.ethernet_type_bidict.update({
    0x0800: IPv4,
})

# tell the encap module that encap  payload type 2 should be mapped to the IPv4 class
ttproto.core.lib.encap.encap_type_bidict.update({
    2: IPv4
})

# map ip next header 41 to the IPv6 class (IPv6 over IPv6)
ip_next_header_bidict.update({
    4: IPv4,
})

#
# Well know Address
#

# TODO
