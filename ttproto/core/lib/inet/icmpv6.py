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


from    ttproto.core.data import *
from    ttproto.core.typecheck import *
from    ttproto.core.lib.inet.meta import *
from    ttproto.core.lib.inet.basics import *
from    ttproto.core.lib.inet.ipv6 import *
from    ttproto.core import exceptions

import ttproto.core.lib.inet.ipv6

__all__ = [
    'ICMPv6',
    'ICMPv6Option',
    'ICMPv6OptionList',
    'ICMPv6LLOption',
    'ICMPv6SLLOption',
    'ICMPv6TLLOption',
    'ICMPv6SLL',
    'ICMPv6TLL',
    'ICMPv6PIOption',
    'ICMPv6PI',
    'ICMPv6NeighborSolicitation',
    'ICMPv6NeighborAdvertisement',
    'ICMPv6NSol',
    'ICMPv6NAdv',
    'ICMPv6RouterSolicitation',
    'ICMPv6RouterAdvertisement',
    'ICMPv6RSol',
    'ICMPv6RAdv',
    'ICMPv6EchoRequest',
    'ICMPv6EchoReply',
    'ICMPv6EReq',
    'ICMPv6ERep',
    'ICMPv6DestinationUnreacheable',
    'ICMPv6Unre',
]


class _ICMPv6OptLengthDescription:
    def __getitem__(self, item):
        return "%d bytes" % (item * 8)


"""
defined in [RFC4443]

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                         Message Body                          +
      |                                                               |


"""


class ICMPv6(
    metaclass=InetPacketClass,
    fields=[
        ("Type", "type", UInt8, InetVariant()),
        ("Code", "code", UInt8, 0),
        ("Checksum", "chk", Hex(UInt16), InetIPv6Checksum()),
        ("Payload", "pl", Value)
    ],
    descriptions={
        "Type": {
            # source: http://www.iana.org/assignments/icmpv6-parameters
            1: "Destination Unreachable",
            2: "Packet Too Big",
            3: "Time Exceeded",
            4: "Parameter Problem",
            128: "Echo Request",
            129: "Echo Reply",
            130: "Multicast Listener Query",
            131: "Multicast Listener Report",
            132: "Multicast Listener Done",
            133: "Router Solicitation",
            134: "Router Advertisement",
            135: "Neighbor Solicitation",
            136: "Neighbor Advertisement",
            137: "Redirect Message",
            138: "Router Renumbering",
            139: "ICMP Node Information Query",
            140: "ICMP Node Information Response",
            141: "Inverse Neighbor Discovery Solicitation Message",
            142: "Inverse Neighbor Discovery Advertisement Message",
            143: "Version 2 Multicast Listener Report",
            144: "Home Agent Address Discovery Request Message",
            145: "Home Agent Address Discovery Reply Message",
            146: "Mobile Prefix Solicitation",
            147: "Mobile Prefix Advertisement",
            148: "Certification Path Solicitation Message",
            149: "Certification Path Advertisement Message",
            150: "Seamoby",
            151: "Multicast Router Advertisement",
            152: "Multicast Router Solicitation",
            153: "Multicast Router Termination",
            154: "FMIPv6 Messages",

            # defined in [I-D.6lowpan-nd-15]: (FIXME)
            31: "Address Registration Option (TBD1)",
            32: "6LoWPAN Context Option (TBD2)",
            33: "Authoritative Border Router Option (TBD3)",

        },
    }):
    @typecheck
    def find_type(self: is_flat_value, type_: is_type) -> optional(Value):
        result = super().find_type(type_)
        if result is not None:
            return result

        # try in the option list
        try:
            options = self["Options"]
        except exceptions.UnknownField:
            return None

        return None if options is None else options.find_type(type_)


"""
defined in [RFC4861]:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Type      |    Length     |              ...              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                              ...                              ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


class ICMPv6Option(
    metaclass=InetPacketClass,
    fields=[
        ("Type", "type", UInt8, InetVariant()),
        ("Length", "len", UInt8, InetLength(unit=8)),
        ("Value", "val", bytes, b""),
    ],
    descriptions={
        "Type": {
            # Registry Name: IPv6 Neighbor Discovery Option Formats
            # source: http://www.iana.org/assignments/icmpv6-parameters
            1: "Source Link-layer Address",
            2: "Target Link-layer Address",
            3: "Prefix Information",
            4: "Redirected Header",
            5: "MTU",
            6: "NBMA Shortcut Limit Option",
            7: "Advertisement Interval Option",
            8: "Home Agent Information Option",
            9: "Source Address List",
            10: "Target Address List",
            11: "CGA option",
            12: "RSA Signature option",
            13: "Timestamp option",
            14: "Nonce option",
            15: "Trust Anchor option",
            16: "Certificate option",
            17: "IP Address/Prefix Option",
            18: "New Router Prefix Information Option",
            19: "Link-layer Address Option",
            20: "Neighbor Advertisement Acknowledgment Option",
            23: "MAP Option",
            24: "Route Information Option",
            25: "Recursive DNS Server Option",
            26: "RA Flags Extension Option",
            27: "Handover Key Request Option",
            28: "Handover Key Reply Option",
            29: "Handover Assist Information Option",
            30: "Mobile Node Identifier Option",
            31: "DNS Search List Option",
            32: "Proxy Signature (PS)",
            138: "CARD Request option",
            139: "CARD Reply option",
            253: "RFC3692-style Experiment 1",
            254: "RFC3692-style Experiment 2",
        },
        "Length": _ICMPv6OptLengthDescription(),
    }):
    pass


class ICMPv6OptionList(
    metaclass=InetUnorderedListClass,
    content_type=ICMPv6Option):
    pass


"""
defined in [RFC4861]:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |    Length     |    Link-Layer Address ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


class ICMPv6LLOption(
    metaclass=InetPacketClass,
    variant_of=ICMPv6Option,
    prune=-1,
    fields	= [
		("LinkLayerAddress",	"hw",	ICMPv6LLAddress, b""),
	]):
	pass

class ICMPv6SLLOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6LLOption,
	id         = 1,
	):
	pass

class ICMPv6TLLOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6LLOption,
	id         = 2,
	):
	pass
"""
defined in [RFC4861]:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Valid Lifetime                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Preferred Lifetime                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Reserved2                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                            Prefix                             +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

class ICMPv6PIOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Option,
	prune      = -1,
	id         = 3,
	fields     = [
		("PrefixLength", 	"pflen" ,UInt8,		64),
		("L",			"l",	bool,		1),
		("A",			"a",	bool,		1),
		("Reserved1", 		"rsv1",	Bin (UInt6),	0),
		("ValidLifetime",	"vlt",	UInt32,		2592000),
		("PreferedLifetime",	"plt",	UInt32,		604800),
		("Reserved2", 		"rsv2",	Hex (UInt32),	0),
		("Prefix",		"pf",	IPv6Address,	"2001:DB8::"),
	]):
	pass

"""
defined in [RFC4443]:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Identifier          |        Sequence Number        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Data ...
      +-+-+-+-+-

"""
class ICMPv6Echo (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6,
	prune      = -1,
	fields     = [
		("Identifier",		"id",	Hex (UInt16),	0),
		("SequenceNumber",	"seq",	UInt16, 	0),
		("Payload", 		"pl",	Value),
	]):
	pass

class ICMPv6EchoRequest (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Echo,
	id         = 128,		): pass


class ICMPv6EchoReply (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Echo,
	id         = 129,		): pass

"""
defined in [RFC4443]:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Unused                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    As much of invoking packet                 |
      +                as possible without the ICMPv6 packet          +
      |                exceeding the minimum IPv6 MTU [IPv6]          |

"""
class ICMPv6DestinationUnreacheable (
	metaclass	= InetPacketClass,
	variant_of	= ICMPv6,
	prune		= -1,
	id	   	= 1,
	fields		= [
		("Unused",		"un",	Hex (UInt32),	0),
		("Payload",		"pl",	IPv6,		0),
	],
	descriptions = {
	"Code": {
		0:	"No route to destination",
		1:	"Communication with destination administratively prohibited",
		2:	"Beyond scope of source address",
		3:	"Address unreachable",
		4:	"Port unreachable",
		5:	"Source address failed ingress/egress policy",
		6:	"Reject route to destination",
	}}):
	pass


"""
defined in [RFC4861]:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Reserved                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                       Target Address                          +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

"""
class ICMPv6NeighborSolicitation (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6,
	prune      = -1,
	id         = 135,
	fields     = [
		("Reserved",		"rsv",	Hex (UInt32),	0),
		("TargetAddress",	"tgt",	IPv6Address,	"::"),
		("Options",		"opt",	ICMPv6OptionList, []),
	]):
	pass

"""
defined in [RFC4861]:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |R|S|O|                     Reserved                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                       Target Address                          +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Options ...
      +-+-+-+-+-+-+-+-+-+-+-+-

"""
class ICMPv6NeighborAdvertisement (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6,
	prune      = -1,
	id         = 136,
	fields     = [
		("Flags", 		"fl",	Hex (UInt16),	0),	# TODO: define the bits
		("Reserved", 		"rsv",	Hex (UInt16),	0),
		("TargetAddress",	"tgt",	IPv6Address,	"::"),
		("Options",		"opt",	ICMPv6OptionList, []),
	]):
	pass

"""
defined in [RFC4861]:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            Reserved                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

"""
class ICMPv6RouterSolicitation (
	metaclass	= InetPacketClass,
	variant_of	= ICMPv6,
	prune		= -1,
	id 		= 133,
	fields		= [
		("Reserved",		"rsv",	Hex (UInt32),	0),
		("Options",		"opt",	ICMPv6OptionList, []),
	]):
	pass

"""
defined in [RFC4861]:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Reachable Time                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Retrans Timer                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

"""
class ICMPv6RouterAdvertisement (
	metaclass	= InetPacketClass,
	variant_of	= ICMPv6,
	prune		= -1,
	id 		= 134,
	fields		= [
		("CurHopLimit",		"hp",	UInt8,		0),
		("Managed",		"m",	bool,		0),
		("Other",		"o",	bool,		0),
		("HomeAgent",		"ha",	bool,		0),
		("RouterPreference",	"rp",	UInt2,		0),
		("Proxied",		"p",	bool,		0),
		("Reserved",		"rsv",	UInt2,		0),
		("RouterLifetime",	"rlt",	UInt16,		1800),
		("ReachableTime",	"tm",	UInt32,		0),
		("RetransTimer",	"rt",	UInt32,		0),
		("Options",		"opt",	ICMPv6OptionList, []),
	]):
	pass


# Aliases
ICMPv6NSol = ICMPv6NeighborSolicitation
ICMPv6NAdv = ICMPv6NeighborAdvertisement
ICMPv6RSol = ICMPv6RouterSolicitation
ICMPv6RAdv = ICMPv6RouterAdvertisement
ICMPv6EReq = ICMPv6EchoRequest
ICMPv6ERep = ICMPv6EchoReply
ICMPv6Unre = ICMPv6DestinationUnreacheable
ICMPv6SLL = ICMPv6SLLOption
ICMPv6TLL = ICMPv6TLLOption
ICMPv6PI = ICMPv6PIOption

# tell the ipv6 module that ip next header 58 should be mapped to the ICMPv6 class
ttproto.core.lib.inet.ipv6.ip_next_header_bidict.update({
	58:	ICMPv6,
})
