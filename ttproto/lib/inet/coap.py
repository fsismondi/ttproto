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
#	- draft-ietf-core-coap-12
#	- draft-ietf-core-block-10
#	- draft-ietf-core-observe-07
#  

from	ttproto.data		import *
from	ttproto.typecheck	import *
from	ttproto.subtype		import SubtypeClass
from	ttproto.union		import UnionClass
from	ttproto.lib.inet.meta	import *
from	ttproto.lib.inet.basics	import *
from	ttproto			import exceptions
from	ttproto.templates	import Range, Length
from	ttproto.primitive	import IntValue

import	ttproto.lib.inet.udp

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
	'CoAPOptionJump',
	'CoAPOptionLength',
	'CoAPOptionLengthTag',
	'CoAPOptionList',
	'CoAPOptionLocationPath',
	'CoAPOptionLocationQuery',
	'CoAPOptionMaxAge',
	'CoAPOptionObserve',
	'CoAPOptionProxyUri',
	'CoAPOptionSize',
	'CoAPOptionString',
	'CoAPOptionToken',
	'CoAPOptionUInt',
	'CoAPOptionUriHost',
	'CoAPOptionUriPath',
	'CoAPOptionUriPort',
	'CoAPOptionUriQuery',
	'CoAPCode',
	'CoAPType',
]

class CoAPOptionLength (metaclass = SubtypeClass (Range (int, 0, 271))):
		
		@typecheck
		def _build_message (self) -> is_flatvalue_binary:

			if self < 15:
				return self, (bytes ((self << 4,)), 4)

			if self > 1034:
				raise Exception ("CoAP option length is too big (>1034)")

			v = self - 15

			nb = v // 255
			v  = v %  255
			return self, BinarySlice (bytes ((0x0f,) + (0xff,) * nb + (v,)), left_bits = 4).as_binary()

		@classmethod
		@typecheck
		def decode_message (cls, bin_slice: BinarySlice) -> is_flatvalue_binslice:
			
			# decode the first 4 bits
			acc = bin_slice[0] >> 4
			bin_slice = bin_slice.shift_bits (4)

			if acc < 15:
				# 4 bits
				return cls (acc), bin_slice

			
			while acc <= 780:
				# more bytes
				v = bin_slice[0]
				bin_slice = bin_slice[1:]

				acc += v

				if v != 255:
					# end of length-field
					return cls (acc), bin_slice
					
			raise Exception ("Malformed CoAP option length (>1034)")

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

class _CoAPBlockUInt (IntValue):
		
		@typecheck
		def _build_message (self) -> is_flatvalue_binary:

			a = self & 0xff000
			b = self & 0x00ff0
			c = self & 0x0000f

			buff = bytes ((a >> 12,)) if a else b""

			if a or b:
				buff += bytes ((b >> 4,))

			buff += bytes ((c << 4,))

			return self, (buff, 4)

		@classmethod
		@typecheck
		def _decode_message (cls, bin_slice: BinarySlice) -> is_flatvalue_binslice:
			num = 0
			for c in bin_slice:
				num = num << 8 | c

			num = num >> 4

			return cls (num), bin_slice.shift_bits (len (bin_slice)*8 - 4)

"""
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | Option Delta  |    Length     | for 0..14
   +---+---+---+---+---+---+---+---+
   |   Option Value ...
   +---+---+---+---+---+---+---+---+
                                               for 15..270:
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   | Option Delta  | 1   1   1   1 |          Length - 15          |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   |   Option Value ...
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
"""

class CoAPOptionLengthTag(InetLength):
	def compute (self, seq, values_bins):
		return super().compute(seq, values_bins) - 1 # remove the delta & length fields

	def post_decode (self, ctx, value):
		end_slice = ctx.remaining_slice[value:]
		def cleaner():
			ctx.remaining_slice = end_slice
		ctx.push_cleaner(cleaner)
			
		ctx.remaining_slice = ctx.remaining_slice[:value]

class CoAPOption (
	metaclass = InetPacketClass, 
	fields    = [
		("Delta",	"dlt",	UInt4,		0),
		("Length",	"len",	CoAPOptionLength, CoAPOptionLengthTag()),
		("Value",	"val",	bytes,		b""),
	]):

	def __init__ (self, *k, **kw):
		if len(k) == 1:
			kw["val"] = k[0]
			k = ()
		super().__init__ (*k, **kw)

class _CoAPJumpValue (
	metaclass	= UnionClass,
	types		= (Omit, UInt8, UInt16)
):
	__map = {0: Omit, 1: UInt8, 2: UInt16}

	@classmethod
	def _decode_message (cls, bin_slice, count = None):
		try:
			# infer the value type from the size of the slice
			type_ = cls.__map[len (bin_slice)]
		except KeyError:
			raise Exception ("Unknown Jump option format: 0xf%x" % len (bin_slice))

		return type_.decode_message (bin_slice)
			


class CoAPOptionJump (
	metaclass	= InetPacketClass,
	variant_of	= CoAPOption,
	prune		= 1,
	fields = [
		("Length",	"len",	UInt4,	InetLength()),
		("Value",	"val",	_CoAPJumpValue),
	]):
	pass



class CoAPOptionList (
	metaclass = InetOrderedListClass,
	content_type = CoAPOption):

	@classmethod
	def _decode_message (cls, bin_slice, count = None):

		values = []
		current = 0

		def decode_field():
			nonlocal bin_slice, current

			# get the delta and compute the option type
			first_byte = bin_slice[0]
			delta = first_byte >> 4

			if first_byte == 0xf0 and count == 15:
				# End-of-options marker
				current = None
				t = CoAPOptionEnd
			else:
				if delta == 15:
					# Jump option
					jmp, bin_slice = CoAPOptionJump.decode_message (bin_slice)
					values.append (jmp)

					if first_byte == 0xf1:
						# 1-byte Jump
						current += 15
					elif first_byte == 0xf2:
						# 2-byte Jump
						current += (jmp["val"] + 2) * 8
					elif first_byte == 0xf3:
						# 3-byte Jump
						current += (jmp["val"] + 258) * 8
					else:
						raise Exception ("Unrecognised Jump option: 0x%x" % first_byte)

					# processe the next option
					first_byte = bin_slice[0]
					delta = first_byte >> 4
				
				current += delta
				t = CoAPOption.get_variant_type(current)
			
			# decode the option according to its type
			v, bin_slice = t.decode_message (bin_slice)

			values.append (v)

		try:		
			if count == None:
				# decode until the end of the slice
				while bin_slice:
					decode_field()
			elif count == 15:
				# decode until the end-of-options marker
				while current != None:
					decode_field()
			else:
				# decode exactly 'count' entries
				for i in range (count):
					decode_field()
			
		except Exception as e:
			exceptions.push_location (e, cls, str(len(values)))
			raise

		return cls (values), bin_slice

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

			# draft-ietf-core-block-08
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

"""
     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  OC   |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
class CoAP (
	metaclass = InetPacketClass, 
	fields    = [
		("Version", 		"ver",		UInt2,		1),
		("Type",		"type",		CoAPType,	0),
		("OptionCount",		"oc",		UInt4,  	InetCount("opt")),
		("Code", 		"code", 	CoAPCode,	0),
		("MessageID", 		"mid",	 	Hex (UInt16),	0),
		("Options", 		"opt",	 	CoAPOptionList,	()),
		("Payload", 		"pl",	 	Value,		b""),
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
		"OptionCount": (lambda oc: "15 or more options" if oc == 15 else None),
	}):

	@typecheck
	def is_request (self: is_flat_value):
		return 0 < self["code"] < 32

	@typecheck
	def is_response (self: is_flat_value):
		return self["code"] >= 32

	def get_uri (self, location = False):
		assert is_flat_value (self)
		host = ""
		port = ""
		path = ""
		query= ""
		for opt in self["opt"]:
			if not location:
				if isinstance (opt, CoAPOptionUriHost):
					host = opt["val"]
				elif isinstance (opt, CoAPOptionUriPort):
					port = str (opt["val"])
				elif isinstance (opt, CoAPOptionUriPath):
					path += "/" + quote_plus (opt["val"])
				elif isinstance (opt, CoAPOptionUriQuery):
					query += ("&" if query else "?") + quote_plus (opt["val"], safe = "=")
			else:
				if isinstance (opt, CoAPOptionLocationPath):
					path += "/" + quote_plus (opt["val"])
				elif isinstance (opt, CoAPOptionLocationQuery):
					query += ("&" if query else "?") + quote_plus (opt["val"], safe = "=")

		if not path and not location:
			path = "/"
		
		return "".join ((host, (":" if host or port else ""), port, path, query))

	def describe (self, desc):
		t = self.get_description ("type")
		if self["mid"]:
			t += " %d" % self["mid"]

		desc.info = "CoAP [%s] %s %s" % (
			t,
			self.get_description ("code"),
			self.get_uri (self["code"] >= 32) if self["code"] else "",
		)
		return True

	def _build_message (self):
		# Building CoAP messages
		#
		# Before calling InetPacket._build_message(), we must first
		# fill the delta fields in the options (and possibly adding
		# interleaving some new options)

		assert self.is_flat()
		
		# generate a new packet
		values = list (self)

		options = self["Options"]
		option_count = None

		# We will fill the deltas only if all deltas are unset
		if options and all (opt["Delta"] == None for opt in options):

			# group the options by type
			by_type = {}
			for opt in options:
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
			option_count = 0
			opt_list = []
			for t in type_list:
				for opt in by_type[t]:
					delta = t - current

					assert 0 <= delta

					if delta > 14:
						# insert a Jump option

						if delta <= 29: # 15 + 14
							# 1-byte Jump Option
							delta = 15
							jump_value = Omit()

						elif delta <= 2070: # (255+2)*8 + 14
							# 2-byte Jump Option

							# max delta -> (255+2) * 8
							delta = 2056 if delta > 2056 else (delta//8*8)
							
							jump_value = UInt8 (delta // 8 - 2)
						
						elif delta <= 526358: # (65535+258)*8 + 14
							# 3-byte Jump Option

							# max delta -> (65535+258)*8
							delta = 526344 if delta > 526344 else (delta//8*8)

							jump_value = UInt16 (delta // 8 - 258)

						else:
							raise Exception("Delta is too big for generating a jump option: %d" % delta)
						current += delta
						opt_list.append (CoAPOptionJump (dlt=15, val=jump_value))


						delta = t - current
						
					assert 0 <= delta <= 14

					current = t

					v = list(opt)
					v[0] = delta
					opt_list.append (type(opt)(*v))

					option_count += 1

			# append the end-of-options marker if needed
			if option_count >= 15:
				option_count = 15
				opt_list.append (CoAPOptionEnd (dlt=15, len=0))

			# replace the options field
			values[self.get_field_id("Options")] = opt_list
		
		# fill the option count field if needed
		if (option_count is not None) and (self["oc"] is None):
			values[self.get_field_id ("oc")] = option_count

		# overwrite the current value
		self = type(self) (*values)

		# call InetPacket._build_message()
		return super()._build_message()

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
		("Number",		"num",	_CoAPBlockUInt,	0),
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
		# draft-ietf-core-coap-12
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
		(15,	"UriQuery",		"String",	(1, 255),	None),
		(16,	"Accept",		"UInt",		(0, 2),		_content_format_description),
		(19,	"Token",		"",		(1, 8),		None),
		(20,	"LocationQuery",	"String",	(0, 255),	None),
		(35,	"ProxyUri",		"String",	(1, 1034),	None),
		
		# draft-ietf-core-block-10

		(27,	"Block1",		"Block",	(0, 3),		None),
		(23,	"Block2",		"Block",	(0, 3),		None),
		(28,	"Size",			"UInt",		(0, 4),		None),

		# draft-ietf-core-observe-07

		(6,	"Observe",		"UInt",		(0, 2),		None),
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
	ttproto.lib.inet.udp.udp_port_map[port] = CoAP

