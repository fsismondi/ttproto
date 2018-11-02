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
#

#
# CoAP message format based on:
#	- draft-ietf-core-coap-18
#	- draft-ietf-core-block-14
#	- draft-ietf-core-observe-11
#

from	ttproto.core.data		import *
from	ttproto.core.typecheck	import *
from	ttproto.core.subtype		import SubtypeClass
from	ttproto.core.union		import UnionClass
from	ttproto.core.packet		import PacketValue
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.lib.inet.basics	import *
from	ttproto.core			import exceptions
from	ttproto.core.templates	import Range, Length
from	ttproto.core.primitive	import IntValue

import	ttproto.core.lib.inet.udp

from urllib.parse import quote_plus


__all__ = [
    'CoAP',
    'CoAPOption',
    'CoAPOptionAccept',
    'CoAPOptionBlock',
    'CoAPOptionBlock1',
    'CoAPOptionBlock2',
    'CoAPOptionContentFormat',
    'CoAPOptionETag',
    'CoAPOptionEmpty',
    'CoAPOptionIfMatch',
    'CoAPOptionIfNoneMatch',
    'CoAPOptionList',
    'CoAPOptionLocationPath',
    'CoAPOptionLocationQuery',
    'CoAPOptionMaxAge',
    'CoAPOptionObserve',
    'CoAPOptionProxyUri',
    'CoAPOptionProxyScheme',
    'CoAPOptionSize1',
    'CoAPOptionSize2',
    'CoAPOptionString',
    'CoAPOptionUInt',
    'CoAPOptionUriHost',
    'CoAPOptionUriPath',
    'CoAPOptionUriPort',
    'CoAPOptionUriQuery',
    'CoAPOptionOneM2MFrom',
    'CoAPOptionOneM2MRequestIdentifier',
    'CoAPOptionOneM2MName',
    'CoAPOptionOneM2MNotificationURI',
    'CoAPOptionOneM2MResponseStatusCode',
    'CoAPOptionOneM2MGroupRequestIdentifier',
    'CoAPOptionOneM2MTY',
    'CoAPCode',
    'CoAPType',

]

class _CoAPOptionHdrInt (metaclass = SubtypeClass (Range (int, 0, 65804))):
    pass

class _CoAPUInt (IntValue):

        @typecheck
        def _build_message (self) -> is_flatvalue_binary:

            result = b""
            v = self

            while v > 0:
                result = bytes((v & 0xff,)) + result
                v >>= 8

            return self, result

        @classmethod
        @typecheck
        def _decode_message (cls, bin_slice: BinarySlice) -> is_flatvalue_binslice:
            result = 0

            for c in bin_slice:
                result = result << 8 | c


            return cls(result), bin_slice[len (bin_slice):]


"""
     0   1   2   3   4   5   6   7
   +---------------+---------------+
   |               |               |
   |  Option Delta | Option Length |   1 byte
   |               |               |
   +---------------+---------------+
   \                               \
   /         Option Delta          /   0-2 bytes
   \          (extended)           \
   +-------------------------------+
   \                               \
   /         Option Length         /   0-2 bytes
   \          (extended)           \
   +-------------------------------+
   \                               \
   /                               /
   \                               \
   /         Option Value          /   0 or more bytes
   \                               \
   /                               /
   \                               \
   +-------------------------------+

   Option Delta:
   Option Length:  4-bit unsigned integer.  A value between 0 and 12
      indicates the length of the Option Value, in bytes.  Three values
      are reserved for special constructs:

      13:  An 8-bit unsigned integer precedes the Option Value and
         indicates the Option Length minus 13.

      14:  A 16-bit unsigned integer in network byte order precedes the
         Option Value and indicates the Option Length minus 269.

      15:  Reserved for future use.  If the field is set to this value,
         it MUST be processed as a message format error.
"""

class CoAPOption (
    metaclass = InetPacketClass,
    fields    = [
        ("Delta",	"dlt",	_CoAPOptionHdrInt,	0),
        ("Length",	"len",	_CoAPOptionHdrInt,	0),
        ("Value",	"val",	bytes,		b""),
    ]):

    def __init__ (self, *k, **kw):
        if len(k) == 1:
            kw["val"] = k[0]
            k = ()
        super().__init__ (*k, **kw)

    def _encode_delta_length (self, delta, length):
        def encode_int (v):
            if v >= 0:
                if v <= 12:
                    return v, b""
                elif v <= 268:
                    v -= 13
                    return 13, bytes((v,))
                elif v <= 65804:
                    v -= 269
                    return 14, bytes(((v // 256), (v % 256)))

            raise Exception ("Invalid option length/delta: %d" % v)

        d, ext_d = encode_int (delta)
        l, ext_l = encode_int (length)

        dl = bytes ((d*16 + l,))

        return dl + ext_d + ext_l

    def _build_message (self):
        length = self["len"]

        # prepare the fields and values
        fields = list (self.fields())
        values = self._fill_default_values()

        # do not build body for CoAPOptionEmpty (nothing to build)
        if isinstance(self,CoAPOptionEmpty):
            body_bin = b''
        else:
            # assemble the body of the option
            values[2:], bins = zip(*(f.tag.build_message (v) for v,f in zip(values[2:], fields[2:])))
            body_bin = concatenate (bins)


        if not isinstance (body_bin, bytes):
            raise Exception ("Option value length is not a multiple of 8 bits")

        # compute the option length if unset
        if length is None:
            values[1] = len (body_bin)

        # encode the delta & length
        dl_bin = self._encode_delta_length(values[0], values[1])

        return type(self) (*values), (dl_bin+body_bin)

    @classmethod
    def _decode_body (cls, values, bin_slice):
        fields = list(cls.fields())[2:]
        try:
            for field in fields:
                v, bin_slice = field.tag.decode_message (field.type, bin_slice)
                values.append (v)

            return bin_slice
        except Exception as e:
            exceptions.push_location (e, cls, field.name)
            raise

    @classmethod
    def _decode_message (cls, bin_slice, previous_type = None):

        # decode the delta & length
        d = bin_slice[0] >> 4
        l = bin_slice[0] &  0xf
        bin_slice = bin_slice[1:]

        def decode_int (v):
            nonlocal bin_slice
            if v == 13:
                v = 13 + bin_slice[0]
                bin_slice = bin_slice[1:]
            elif v == 14:
                v = 269 + bin_slice[0]*256 + bin_slice[1]
                bin_slice = bin_slice[2:]
            return v

        delta  = decode_int (d)
        length = decode_int (l)

        if previous_type is not None:
            option_type = previous_type + delta

            cls = cls.get_variant_type (option_type)

        # decode the other fields
        remaining_slice = bin_slice[length:]
        bin_slice       = bin_slice[:length]

        values = [delta, length]

        bin_slice = cls._decode_body(values, bin_slice)
        if bin_slice:
            raise Exception ("CoAP Option not fully decoded: %d bytes left in the buffer" % len(bin_slice))

        # create the packet
        return cls (*values), remaining_slice


class CoAPOptionList (
    metaclass = InetOrderedListClass,
    content_type = CoAPOption):

    @classmethod
    def _decode_message (cls, bin_slice, count = None):

        values = []
        current = 0

        try:
            while bin_slice and bin_slice[0] != 0xff:
                opt, bin_slice = CoAPOption._decode_message (bin_slice, current)

                current += opt["Delta"]
                values.append (opt)

        except Exception as e:
            exceptions.push_location (e, cls, str(len(values)))
            raise

        return cls (values), bin_slice

    def _build_message (self):

        assert self.is_flat()

        # If option deltas are unset, then we fill them and reorder the options if necessary
        #
        if all (opt["Delta"] is None for opt in self):

            # group the options by type
            by_type = {}
            for opt in self:
                t = opt.get_variant_id()
                lst = by_type.get (t)
                if lst is None:
                    by_type[t] = [opt]
                else:
                    lst.append (opt)

            # fill the deltas and generate the option list
            type_list = list (by_type)
            type_list.sort()
            current = 0
            values = []
            for t in type_list:
                for opt in by_type[t]:
                    delta   = t - current
                    current = t

                    v = list(opt)
                    v[0] = delta
                    values.append (type(opt)(*v))

            # overwrite the current value
            self = type(self) (values)

        # call InetList._build_message()
        return super()._build_message()

class _CoAPCodeDescription:
    __known_codes = {
            # Null message
            0:	"Empty",

            # Methods
            1:	"GET",
            2:	"POST",
            3:	"PUT",
            4:	"DELETE",

            # Responses
            65:	"2.01 Created",
            66:	"2.02 Deleted",
            67:	"2.03 Valid",
            68:	"2.04 Changed",
            69:	"2.05 Content",
            128:	"4.00 Bad Request",
            129:	"4.01 Unauthorized",
            130:	"4.02 Bad Option",
            131:	"4.03 Forbidden",
            132:	"4.04 Not Found",
            133:	"4.05 Method Not Allowed",
            134:	"4.06 Not Acceptable",
            140:	"4.12 Precondition Failed",
            141:	"4.13 Request Entity Too Large",
            143:	"4.15 Unsupported Media Type",
            160:	"5.00 Internal Server Error",
            161:	"5.01 Not Implemented",
            162:	"5.02 Bad Gateway",
            163:	"5.03 Service Unavailable",
            164:	"5.04 Gateway Timeout",
            165:	"5.05 Proxying Not Supported",

            # draft-ietf-core-block-14
            95:	"2.31 Continue",
            136:	"4.08 Request Entity Incomplete",
        }
    __responses_groups = (
        'Reserved',
        'Reserved',
        'Success',
        'Reserved',
        'Client Error',
        'Server Error',
    )

    def __getitem__ (self, item):
        try:
            return self.__known_codes[item]
        except KeyError:
            if 1 <= item <= 31:
                return "Request %d" % item
            elif 64 <= item <= 191:
                major = item // 32
                minor = item %  32
                return "%d.%02d %s" % (major, minor, self.__responses_groups[major])
            else:
                return "Reserved"


class CoAPType (UInt2):
    __values = "CON", "NON", "ACK", "RST"

    def __new__ (cls, value):
        if isinstance (value, str):
            try:
                value = cls.__values.index (value.upper())
            except ValueError:
                raise Exception ("Invalid CoAP message type")

        return super().__new__(cls, value)


class CoAPCode (UInt8):
    __values = "Empty", "GET", "POST", "PUT", "DELETE"

    def __new__ (cls, value):
        if isinstance (value, str):
            try:
                value = cls.__values.index (value.upper())
            except ValueError:
                raise Exception ("Invalid CoAP code")
        elif isinstance (value, float):
            major = int (value)
            minor = round ((value-major)*100)
            if not (0 <= major < 8) or not (0 <= minor < 32):
                raise Exception ("Invalid CoAP code")
            value = major*32 + minor

        return super().__new__(cls, value)


class _CoAPPayloadTag (PacketValue.Tag):
    def build_message (self, value, ctx = None):
        v, b = value.build_message()
        if b:
            # prepend the payload marker
            b = concatenate ((b"\xff", b))
        return v, b

    def decode_message (self, type_, bin_slice, ctx = None):
        if bin_slice and bin_slice[0] == 0xff:
            # payload present
            # -> skip the marker
            return type_.decode_message (bin_slice[1:])
        else:
            return b"", bin_slice


"""
     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  TKL  |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

class CoAP (
    metaclass = InetPacketClass,
    fields    = [
        ("Version", 		"ver",		UInt2,		1),
        ("Type",		"type",		CoAPType,	0),
        ("TokenLength",		"tkl",		UInt4,		InetLength("Token")),
        ("Code", 		"code", 	CoAPCode,	0),
        ("MessageID", 		"mid",	 	Hex (UInt16),	0),
        ("Token",		"tok",		bytes,		b""),
        ("Options", 		"opt",	 	CoAPOptionList,	()),
        ("Payload", 		"pl",	 	Value,		_CoAPPayloadTag (b"")),
    ],
    descriptions = {
        "Version": {
            1:	"draft-ietf-core-coap",
        },
        "Type": {
            0:	"CON",
            1:	"NON",
            2:	"ACK",
            3:	"RST",
        },
        "Code": _CoAPCodeDescription(),
    }):

    @typecheck
    def is_request (self: is_flat_value):
        return 0 < self["code"] < 32

    @typecheck
    def is_response (self: is_flat_value):
        return self["code"] >= 32

    def get_uri(self, location=False):
        assert is_flat_value(self)
        host = ""
        port = ""
        path = ""
        query = ""
        for opt in self["opt"]:
            if not location:
                if isinstance(opt, CoAPOptionUriHost):
                    host = opt["val"]
                elif isinstance(opt, CoAPOptionUriPort):
                    port = str(opt["val"])
                elif isinstance(opt, CoAPOptionUriPath):
                    path += "/" + quote_plus(opt["val"])
                elif isinstance(opt, CoAPOptionUriQuery):
                    query += ("&" if query else "?") + quote_plus(opt["val"], safe="=")
            else:
                if isinstance(opt, CoAPOptionLocationPath):
                    path += "/" + quote_plus(opt["val"])
                elif isinstance(opt, CoAPOptionLocationQuery):
                    query += ("&" if query else "?") + quote_plus(opt["val"], safe="=")

        if not path and not location:
            path = "/"

        return "".join((host, (":" if host or port else ""), port, path, query))

    def describe(self, desc):
        t = self.get_description("type")

        if self["mid"]:
            t += " mid %d" % self["mid"]

        desc.info = "CoAP [%s] %s %s" % (
            t,
            self.get_description("code"),
            self.get_uri(self["code"] >= 32) if self["code"] else "",
        )

        if self['code'] != 0:
            tok = ''
            if self["tok"]:
                token_as_str = self["tok"].hex()
                for i in range(0, len(token_as_str), 2):
                    tok += "%s " % token_as_str[i:i + 2]
            else:
                tok = 'None'

            desc.info += ', tok %s' % tok

        return True

#############################
# CoAP Options
#############################

##

class CoAPOptionUInt (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOption,
    prune		= -1,
    fields = [
        ("Value",	"val",	_CoAPUInt),
    ]):
    pass


class CoAPOptionEmpty (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOption,
    prune		= -1,
    ):
    pass


class CoAPOptionString (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOption,
    prune		= -1,
    fields = [
        ("Value",	"val",	str),
    ]):
    pass


class CoAPOptionBlock (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOption,
    prune		= -1,
    fields = [
        ("Number",		"num",	int,		0),
        ("M",			"m",	bool,		False),
        ("SizeExponent",	"szx",	UInt3,		0),
    ],
    descriptions	= {
        "szx": lambda szx: ("%d bytes" % (2**(szx+4))),
        "m": {
            0:	"last block",
            1:	"more blocks",
        },
    }):

    def __init__ (self, *k, **kw):
        # bypass CoAPOption.__init__
        return super (CoAPOption, self).__init__ (*k, **kw)

    def get_description_for_value (self, field, value):
        field = self.get_field_id (field)
        if field == 2: # 'Number' option
            szx = self["szx"]
            if value is None or szx is None:
                return None
            else:
                return "offset %d bytes" % (value * (2**(szx+4)))
        else:
            return super().get_description_for_value (field, value)

    @typecheck
    def _build_message (self) -> is_flatvalue_binary:

        values = self._fill_default_values()

        v = _CoAPUInt(
            # block number
            ((values[2] & 0xfffff) << 4)

            # m bit
            | ((values[3] & 1) << 3)

            # size exponent
            | (values[4] & 7)
        )

        v_bin = v.build_message()[1]

        if self["len"] is None:
            values[1] = len(v_bin)

        # encode the delta & length
        dl_bin = self._encode_delta_length(values[0], values[1])

        return type(self) (*values), (dl_bin + v_bin)

    @classmethod
    def _decode_body (cls, values, bin_slice):
        v, bin_slice = _CoAPUInt.decode_message(bin_slice)

        values.append ((v & ~0xf) >> 4)	# num
        values.append ((v & 8) >> 3)	# m
        values.append (v & 7)		# szx

        return bin_slice


class CoAPOptionEnd (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOptionEmpty,
    ):
    pass

##

_content_format_description = {
    0:	"text/plain; charset=utf-8",
    40:	"application/link-format",
    41:	"application/xml",
    42:	"application/octet-stream",
    47:	"application/exi",
    50:	"application/json",
    11542 : "application/vnd.oma.lwm2m+tlv",
    11543 : "application/vnd.oma.lwm2m+json",
}

_ResponseStutusCode_format_description = {
    65: "2001",
    66: "2002",
    67:	"2003",
    68:	"2004",
    69:	"2000",
}

_TY_format_description = {
    "AE": "2",
    "container": "3",
    "contentInstance": "4",
    "accessControlPolicy": "1",
    "subscription": "23",
    "node": "14",
    "remoteCSE": "16",
    "group": "9",
    "pollingChannel": "15",
    "flexContainer" : "28",
    "mgmtCmd": "12",
}
def _max_age_description (v):

    if v == 0:
        return "no caching"

    result = []
    for div, name in (
        (60, "second"),
        (60, "minute"),
        (24, "hour"),
        (365, "day"),
        (99999999, "year"),
    ):
        nb = v %  div
        v  = v // div
        if nb:
            result.append ("%d %s%s" % (nb, name, "s" if nb>1 else ""))

    return ", ".join (reversed (result))

@classmethod
def _coap_option_decode_message (cls, bin_slice):

    # call the parent decoder
    v, bin_slice = cls.__bases__[0]._decode_message (bin_slice)
    v.__class__  = cls  # bless the object (to match our type)

    # ensure that the length of the option is valid
    lmin, lmax = cls._min_max_length
    if not (lmin <= v["len"] <= lmax):
        raise Exception ("Option %s has invalid length %d (should be in [%d..%d])" % (cls.__name__, v["len"], lmin, lmax))

    return v, bin_slice

for i, n, t, l, d in (
        # draft-ietf-core-coap-18
        # (MaxAge is defined separately)

        #No	Name			ParentClass	Min/Max length	description
        (1,	"IfMatch",		"",		(0, 8),		None),
        (3,	"UriHost",		"String",	(1, 255),	None),
        (4,	"ETag",			"",		(1, 8),		None),
        (5,	"IfNoneMatch",		"Empty",	(0, 0),		None),
        (7,	"UriPort",		"UInt",		(0, 2),		None),
        (8,	"LocationPath",		"String",	(0, 255),	None),
        (11,	"UriPath",		"String",	(0, 255),	None),
        (12,	"ContentFormat",	"UInt",		(0, 2),		_content_format_description),
        (14,	"MaxAge",		"UInt",		(0, 4),		_max_age_description),
        (15,	"UriQuery",		"String",	(0, 255),	None),
        (17,	"Accept",		"UInt",		(0, 2),		_content_format_description),
        (20,	"LocationQuery",	"String",	(0, 255),	None),
        (35,	"ProxyUri",		"String",	(1, 1034),	None),
        (39,	"ProxyScheme",		"String",	(1, 255),	None),
        (60,	"Size1",		"UInt",		(0, 4),		None),

        # draft-ietf-core-block-14

        (27,	"Block1",		"Block",	(0, 3),		None),
        (23,	"Block2",		"Block",	(0, 3),		None),
        (28,	"Size2",		"UInt",		(0, 4),		None),

        # draft-ietf-core-observe-11

        (6,	"Observe",		"UInt",		(0, 3),		None),

        # OneM2M binding
        (256, "OneM2MFrom" , "String" , (0, 255) , None),
        (257, "OneM2MRequestIdentifier" , "String" , (0, 255) , None),
        (258, "OneM2MName" , "String" , (0, 255) , None),
        (263, "OneM2MNotificationURI" , "String" , (0, 255) , None),
        (265, "OneM2MResponseStatusCode" , "UInt" , (0, 2) , _ResponseStutusCode_format_description),
        (266, "OneM2MGroupRequestIdentifier" , "String" , (0, 255) , None),
        (267, "OneM2MTY" , "UInt" , (0, 2) , _TY_format_description),
    ):
    exec(
"""
class CoAPOption%s (
    metaclass	= InetPacketClass,
    variant_of	= CoAPOption%s,
    id		= %d,
    descriptions	= {} if d is None else {"Value": d},
    ):
    _min_max_length = %r
    _decode_message = _coap_option_decode_message
""" % (n, t, i, l))


##Aliases
#ICMPv6NSol = ICMPv6NeighborSolicitation
#ICMPv6NAdv = ICMPv6NeighborAdvertisement
#ICMPv6RSol = ICMPv6RouterSolicitation
#ICMPv6RAdv = ICMPv6RouterAdvertisement
#ICMPv6EReq = ICMPv6EchoRequest
#ICMPv6ERep = ICMPv6EchoReply
#ICMPv6Unre = ICMPv6DestinationUnreacheable
#ICMPv6SLL = ICMPv6SLLOption
#ICMPv6TLL = ICMPv6TLLOption
#ICMPv6PI = ICMPv6PIOption


# tell the udp module on which udp ports coap runs
for port in (5683,) + tuple (range (61616, 61632)):
    ttproto.core.lib.inet.udp.udp_port_map[port] = CoAP



from ttproto.core.lib.ieee802154 import Ieee802154

class ZigBeeEncapsulationProtocol (
    metaclass = InetPacketClass,
    fields    = [
        ("Protocol ID string", 		"pid",		Hex(UInt16  ),		0),
        ("Version", 		"ver",		UInt8,		3),
        ("Type",		"type",		UInt8,	0),
        ("Channel",		"ch",		UInt8,		0),
        ("Device ID",		"did",		UInt16,		0),
        ("LQI/CRC Mode",		"mode",		UInt8,		0),
        ("LQI Value",		"lqi",		UInt8,		0),
        ("NTP timestamp (s)",		"nts",		Hex(UInt32),		0),
        ("NTP timestamp fraction (ms)",		"nts_frac",		Hex(UInt32),		0),
        ("Sequence number",		"seq",		UInt32,		0),
        ("stuff",		"stuff",		Hex(UInt80),		0),
        ("Length",		"len",		UInt8,		0),
        ("Payload", 		"pl",	 	Ieee802154),
    ]):
    pass

ttproto.core.lib.inet.udp.udp_port_map[17754] = ZigBeeEncapsulationProtocol


