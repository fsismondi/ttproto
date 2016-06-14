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

from	contextlib	import contextmanager
import	struct, threading

from	ttproto.core.typecheck	import *
from	ttproto.core.exceptions	import Error, push_location
from	ttproto.core.data	import *
from	ttproto.core.subtype	import SubtypeClass
from	ttproto.core.templates	import Range, Length
from	ttproto.core.packet	import *
from	ttproto.core.list	import *
from	ttproto.core.primitive	import IntValue

__all__ = [
	'UnsignedBigEndianIntClass',
	'FixedLengthBytesClass',
	'InetType',
	'InetLength',
	'InetCount',
	'InetVariant',
	'InetIPv6Checksum',
	'InetPaddedPrefix',
	'InetPacketValue',
	'InetPacketClass',
	'InetListValue',
	'InetOrderedListClass',
	'InetUnorderedListClass',
	'Hex',
	'Bin',
]

def UnsignedBigEndianIntClass (size):

	class UnsignedBigEndianIntValue (metaclass = SubtypeClass (Range (int, 0, 2**size))):

		@typecheck
		def _build_message (self) -> is_flatvalue_binary:

			result = []
			v = self
			if not self.__size % 8:
				# multiple of 8 bit
				for s in range (0, self.__size//8):
					result.append (v & 255)
					v >>= 8
				return self, bytes (reversed (result))
			else:
				# not a multiple of 8 bits

				# add padding bits
				v <<= (-self.__size % 8)
				for s in range (0, self.__size//8 + 1):
					result.append (v & 255)
					v >>= 8
				return self, (bytes (reversed (result)), self.__size%8)

		@classmethod
		@typecheck
		def decode_message (cls, bin_slice: BinarySlice) -> is_flatvalue_binslice:
			# decode the int
			v = 0
			nb = cls.__size // 8
			remainder = cls.__size % 8
			if not remainder:
				# multiple of 8 bit
				sl = bin_slice[:nb]
				for i in range (0, nb):
					v = (v << 8) | sl[i]
			else:
				# not a multiple of 8 bits

				# add padding bits
				sl = bin_slice.bit_slice (0, cls.__size)
				for i in range (0, nb):
					v = (v << 8) | sl[i]
				v = (v << remainder) | (sl[nb] >> (8 - remainder))

			return cls (v), bin_slice.shift_bits (cls.__size)

	def MetaclassFunc (name, bases, classdict):
		assert len (bases) == 0 # FIXME: it could be useful to have multiple inheritance in some cases ?

		bases = UnsignedBigEndianIntValue,
		classdict["_UnsignedBigEndianIntValue__size"] = size

		return type (name, bases, classdict)

	return MetaclassFunc


#TODO: remove this function
def value_metaclass (func):

	class TmpMetaclass:
		def __init__ (self, *k, **kw):
			self.__k  = k
			self.__kw = kw

		def __call__ (self, name, bases, classdict):
			new_base = func (*self.__k, **self.__kw)

			# prepend the new base to the provided bases
			bases = (new_base,) + bases

			return type (name, bases, classdict)

	return TmpMetaclass


@value_metaclass
def FixedLengthBytesClass (size: int):

	class FixedLengthBytesValue (metaclass = SubtypeClass (Length (bytes, size))):

		@typecheck
		def __new__ (cls, value = None):
			if value is None:
				value = b"\0" * size
			# TODO: check that the resulting value is valid
			result = super().__new__(cls, value)

			if len (result) != size:
				raise Error ("Invalid value length (%d instead of %d)" % (len (value), size))

			return result

		@classmethod
		def _decode_message (cls, bin_slice):

			return bin_slice[:size].raw(), bin_slice[size:]

		#TODO: support str in __new__ too
		def __str__ (self):
			return ":".join ("%02x" % c for c in self)

	return FixedLengthBytesValue



class __OptFieldRefTag (PacketValue.Tag):
	@typecheck
	def __init__ (self, field_name: optional (str) = None, default = 0):

		super().__init__ (default)
		self.field_name = field_name

	def init (self, *k):
		super().init (*k)
		self.__ref_field_id = None if self.field_name is None else self.get_packet_type().get_field_id(self.field_name)

	def get_ref_id(self):
		return self.__ref_field_id


class _RestartDecodingAs (Exception):
	def __init__ (self, type):
		self.type = type

class InetType (__OptFieldRefTag):
	@staticmethod
	@contextmanager
	def __decode_context (ctx, expected_type: type):
		with ctx.replace_attr ("expected_type", expected_type):
			yield

	@typecheck
	def __init__ (self, bidict: optional (Bidict), field_name: optional (str) = None):
		super().__init__ (field_name)
		self.__bidict = bidict

	def _set_bidict (self, bidict: Bidict):
		assert self.__bidict is None
		self.__bidict = bidict

	def compute (self, seq, values_bins):
		assert self.__bidict is not None  # must have been initialised

		v = seq if self.get_ref_id() is None else values_bins[self.get_ref_id()][0]

		return self.__bidict[:v.get_type()]

	def post_decode (self, ctx, value):
		assert self.__bidict is not None  # must have been initialised

		expected_type = self.__bidict[value]

		if self.get_ref_id() is not None:
			# set a handler -> a 'with' context to change the slice on the fly
			ctx.push_context (self.get_ref_id(), self.__decode_context (ctx, expected_type))
		else:
			# try to change the type on the fly

			# check that we can safely change the variant
			nb_decoded = len (ctx.values)
			v = expected_type
			prune = False
			while v != ctx.variant:
				if v.get_prune_id() < nb_decoded:
					prune = True
				v = v.get_base_variant()

				if v is None:
					raise Error ("The new variant must be based on the current one") # FIXME: this could be relaxed
			try:
				if not (expected_type._decode_message.__func__ is ctx.variant._decode_message.__func__):
					# the new variant has a different _decode_message() function
					# -> we must restart decoding from scratch
					raise _RestartDecodingAs (expected_type)
			except AttributeError:
				pass

			if prune:
				# we have already decode too many fields to be able to change the type on the fly
				# -> restart decoding from the beginning of the packet
				ctx.reset()
				ctx.remaining_slice	= ctx.initial_slice
				ctx.values[:]		= ()
				ctx.field_id		= -1

			# change the variant
			ctx.variant = expected_type


class InetVariant (InetType):
	def __init__ (self):
		super().__init__ (None)

	@typecheck
	def init (self, *k):
		super().init (*k)
		self._set_bidict (self.get_packet_type().get_variants_bidict())


class InetLength (__OptFieldRefTag):
	@staticmethod
	@contextmanager
	def __decode_context (ctx, value):
		# generate a shorter slice
		#TODO: detect possible errors (slice too short)
		with ctx.replace_attr ("remaining_slice", ctx.remaining_slice.bit_slice (0, value)):
			yield

			# ensure that we decoded all the bits
			bl = ctx.remaining_slice.get_bit_length()
			if bl:
				raise Error("Did not decode all the content of the slice (%d bits remaining)" % bl)

		# move forward n bits in the restored slice
		ctx.remaining_slice = ctx.remaining_slice.shift_bits (value)

	@typecheck
	def __init__ (self, field_name: optional (str) = None, unit: int = 1):
		super().__init__ (field_name)
		self.__unit = unit * 8

	def compute (self, seq, values_bins):
		if self.get_ref_id() is None:
			l = 0
			for vb in values_bins:
				l += get_binary_length (vb[1])
		else:
			l = get_binary_length (values_bins[self.get_ref_id()][1])

		if l % self.__unit:
			raise Error ("Invalid length: must be a multiple of %d bytes" % (self.__unit // 8))
		return l // self.__unit

	def post_decode (self, ctx, value):

		value *= self.__unit

		if self.get_ref_id() is None:
			assert ctx.initial_slice.same_buffer_as (ctx.remaining_slice) # we must still be working on the same slice

			right = ctx.initial_slice.get_left() + value
			if right != ctx.initial_slice.get_right():
				remaining_bits = right - ctx.remaining_slice.get_left()
				if remaining_bits < 0:
					raise Error("InetLength: expected length is to small: %d (%d bits), %d bits decoded so far" % (
						value / self.__unit,
						value,
						ctx.remaining_slice.get_left() - ctr.initial_slice.get_left()
					))

				else:
					final_slice = ctx.initial_slice.shift_bits (value)
					# TODO: update the initial_slice too ???
					ctx.remaining_slice = ctx.remaining_slice.bit_slice (0, remaining_bits)

					def cleaner():
						ctx.remaining_slice = final_slice
					ctx.push_cleaner (cleaner)
		else:
			# set a handler -> a 'with' context ! to change the slice on the fly
			ctx.push_context (self.get_ref_id(), self.__decode_context (ctx, value))

class InetCount (__OptFieldRefTag):
	@staticmethod
	@contextmanager
	def __decode_context (ctx, count):
		with ctx.replace_attr ("expected_count", count):
			yield

	@typecheck
	def __init__ (self, field_name: str):
		super().__init__ (field_name)

	def compute (self, seq, values_bins):
		assert self.get_ref_id() is not None

		return len (values_bins[self.get_ref_id()][0])

	def post_decode (self, ctx, value):
		# set a handler -> a 'with' context ! to change the slice on the fly
		ctx.push_context (self.get_ref_id(), self.__decode_context (ctx, value))


class InetIPv6Checksum (PacketValue.Tag):

	def __init__ (self):
		super().__init__ (0)

	def compute (self, seq, values_bins):
		# schedule the computation of the checksum if not set

		try:
			previous_func = seq._post_build_fields
		except AttributeError:
			def previous_func (dummy):
				pass

		def post_build_fields (values_bins):

			# call the previous _post_build_fields function
			previous_func (values_bins)

			# compute the pseudo-header
			src_dst = seq._get_ipv6_pseudo_addresses()
			if not src_dst:
				# no parent IPv6 header -> cannot compute the pseudo-header
				return

			assert len (src_dst[0]) == len(src_dst[1]) == 16 # IPv6 only for the moment

			payload = concatenate (vb[1] for vb in values_bins)
			length = len (payload)

			import ttproto.core.lib.inet.ipv6

			pseudo_msg = bytes().join ((src_dst[0], src_dst[1], struct.pack(">LHBB", length, 0, 0, ttproto.core.lib.inet.ipv6.ip_next_header_bidict[:seq.get_type()]), payload, bytes((0,) if length % 2 else ())))

			# compute the checksum
			chksum = self.checksum (pseudo_msg)

			chksum = (chksum >> 8) | ((chksum & 0xff) << 8)# FIXME: the endianness is not correct

			values_bins[self.get_field_id()] = self.get_field().store_data(chksum).build_message()

		seq._post_build_fields = post_build_fields

		return 0

	@staticmethod
	def carry_around_add (a, b):
		c = a + b
		return (c & 0xffff) + (c >> 16)

	def checksum (self,msg):
		s = 0
		for i in range(0, len(msg), 2):
			w = msg[i] + (msg[i+1] << 8)
			s = self.carry_around_add(s, w)
		return ~s & 0xffff

class InetPaddedPrefix (__OptFieldRefTag):
	@typecheck
	def __init__ (self, pad_step: one_of (16, 32, 64), pf_length_field_name: str):

		super().__init__ (pf_length_field_name, bytes(16))
		self.__step = pad_step

	def build_message (self, value, values_bins):

		v, b = value.build_message()
		assert isinstance (b, bytes) and len (b) == 16  # that's the length of the full prefix

		p_len = values_bins[self.get_ref_id()][0]

		expected_len = (p_len + self.__step - 1) // self.__step * self.__step // 8

		return v, (b[:expected_len] if len(b) > expected_len else b)

	def decode_message (self, type_, bin_slice, ctx):

		expected_len = (ctx.values[self.get_ref_id()] + self.__step - 1) // self.__step * self.__step // 8

		v = bin_slice[:expected_len].raw()
		if expected_len < 16:
			v += bytes(16 - expected_len)

		return type_ (v), bin_slice[expected_len:]


class _DecodeContext:
	def __init__ (self):
		self.__contextes = {}
		self.__cleaners = []

	def reset (self):
		self.__contextes.clear()
		self.__cleaners[:]=()

	@typecheck
	def push_context (self, field_id: int, obj):
		assert hasattr (obj, "__enter__") and hasattr (obj, "__exit__")
#			print "**push context", field_id, obj
		if field_id not in self.__contextes:
			self.__contextes[field_id] = [obj]
		else:
			self.__contextes[field_id].append (obj)

	def pop_context (self, field_id):

		if field_id in self.__contextes:
			l = self.__contextes [field_id]
			if l:
#					print "**pop context", field_id, l[0]
				return l.pop(0)
		return None

	@contextmanager
	def replace_attr (self, name, value):
		backup = getattr (self, name)
		setattr (self, name, value)
		try:
			yield
		finally:
			setattr (self, name, backup)

	def push_cleaner (self, func):
		self.__cleaners.insert(0, func)

	def leave (self):
		for c in self.__cleaners:
			c()

class InetPacketValue (PacketValue):


	### class methods

	@classmethod
	def metaclass_func (cls, *k, variant_of: optional (type) = None, **kw):
		assert variant_of is None or issubclass (variant_of, InetPacketValue)

		result = super().metaclass_func (*k, variant_of = variant_of, **kw)

		i=0
		for f in result.fields():
			if isinstance (f.tag, InetVariant):
				result.__cls_variant_field_id = i
				break
			i+=1
		else:
			result.__cls_variant_field_id = None

		return result

	@classmethod
	def get_variant_field_id (cls):
		return cls.__cls_variant_field_id


	### instance methods

	@typecheck
	def _build_message (self) -> is_flatvalue_binary:

		values_bins = [(v, b"") for v in self._fill_default_values()]
		values_bins = [f.tag.build_message(v_b[0], values_bins) for v_b, f in zip (values_bins, self.fields())]

		i = -1
		for field in self.fields():
			i += 1
			tag = field.tag
			if self[i] is not None or not hasattr(tag, "compute"):
				continue

			values_bins[i] = tag.build_message (field.store_data (tag.compute (self, values_bins), none_is_allowed = False), values_bins)

		if hasattr (self, "_post_build_fields"): #TODO: use a context instead
			self._post_build_fields (values_bins)
			del self._post_build_fields

		values, bins = zip (*values_bins)

		return type(self) (*values), concatenate (bins)

	@typecheck
	def _build_message_ipv6_header (self) -> is_flatvalue_binary:
		"""Specialised method for building an IPv6 heades

		Its purpose is to collect the source/destination addresses
		needed to assemble the pseudo-header when computing a checksum.
		"""

		# index of the src & dst address fields
		id_src = 6
		id_dst = 7

		# fill the values if we dont have any
		# source address
		src, dst = self[6], self[7]

		if src is None:
			src = self.get_field(6).tag.get_default_value()
		if dst is None:
			dst = self.get_field(7).tag.get_default_value()

		with self.ipv6_pseudo_addresses_context ((src, dst)):
			return InetPacketValue._build_message (self)

	__local = threading.local()

	@staticmethod
	@contextmanager
	def ipv6_pseudo_addresses_context (src_dst):
		l = InetPacketValue.__local
		backup = l.pseudo_ipv6_addresses if hasattr(l, "pseudo_ipv6_addresses") else None

		l.pseudo_ipv6_addresses = src_dst
		try:
			yield
		finally:
			l.pseudo_ipv6_addresses = backup

	@staticmethod
	def _get_ipv6_pseudo_addresses():
		l = InetPacketValue.__local
		return l.pseudo_ipv6_addresses if hasattr(l, "pseudo_ipv6_addresses") else None

	@classmethod
	@typecheck
	def __decode_field (cls, ctx: _DecodeContext, field_id: int):

		obj = ctx.pop_context (field_id)
		if obj:
			with obj:
				cls.__decode_field (ctx, field_id)
		else:
			field = ctx.variant.get_field (field_id)

			expected_type = ctx.expected_type if ctx.expected_type else field.type

			assert issubclass (expected_type, field.type) or (field.optional and issubclass (expected_type, Omit))# FIXME: should be checked earlier

			if ctx.expected_count is not None:
				assert ctx.expected_count >= 0

				# Here we generate a wrapper class for the expected type, that will passe the 'count'
				# when decoding the message
				# TODO: find a more generic way to pass arbitraty parameters to the decode function
				#	This is a very ugly hack: we define an inherited class for expected_type
				#	and use a metaclass to overload 'isinstance()' so that Value.decode_message()
				#	does not complain about mismatching types
				expected_type_orig = expected_type
				@classmethod
				def _decode_message (cls, bin_slice):
					return expected_type_orig._decode_message (bin_slice, count = ctx.expected_count)
				class metaclass (type):
					def __subclasscheck__ (self, instance):
						return issubclass (instance, expected_type_orig)
					def __instancecheck__ (self, instance):
						return isinstance (instance, expected_type_orig)
				expected_type = metaclass (expected_type.__name__, (expected_type,), {"_decode_message": _decode_message})

			value, ctx.remaining_slice = field.tag.decode_message (expected_type, ctx.remaining_slice, ctx)

			ctx.values.append (value)

			if hasattr (field.tag, "post_decode"):
				field.tag.post_decode (ctx, value)

#			print "decoded", field.type, repr(value)


	@classmethod
	def _decode_message (cls, bin_slice):

		ctx = _DecodeContext ()
		ctx.expected_type	= None
		ctx.expected_count	= None
		ctx.initial_slice	= bin_slice
		ctx.remaining_slice	= bin_slice
		ctx.values		= []
		ctx.cls			= cls
		ctx.variant		= cls
		ctx.field_id		= 0

		try:
			while ctx.field_id < ctx.variant.get_length():
				cls.__decode_field (ctx, ctx.field_id)

				# TODO: verify the checksum
				ctx.field_id += 1

			ctx.leave()

		except _RestartDecodingAs as e: # TODO: maybe this should be generalised in Value.decode_message()
			return e.type._decode_message (bin_slice)

		except Exception as e:
			push_location (e, ctx.variant, ctx.variant.get_field (ctx.field_id).name)
			raise

		return ctx.variant (*ctx.values), ctx.remaining_slice

InetPacketClass = InetPacketValue.metaclass_func

class InetListValue (ListValue):
	### class methods

	### instance methods
	pass

InetListClass =  InetListValue.metaclass_func

def InetOrderedListClass (name, bases, classdict, content_type):
	return InetListClass (name, bases, classdict, content_type, True)

def InetUnorderedListClass (name, bases, classdict, content_type):
	return InetListClass (name, bases, classdict, content_type, False)


class Hex:
	"""Factory class to display an int in hex format"""

	__instances = {}

	@typecheck
	def __new__ (cls, t = int):
		if t == int:
			t = IntValue

		assert issubclass (t, IntValue)

		try:
			return cls.__instances[t]
		except KeyError:

			new_type = type (t.__name__, (t,), {})
			try:
				s = new_type._UnsignedBigEndianIntValue__size
			except AttributeError:
				def __str__ (self):
					return hex (self)
			else:
				def __str__ (self):
					return ("-0x" if self < 0 else "0x") + format (abs (self), self.__format)
				new_type.__format = "0%dx" % ((s + 3) / 4)

			new_type.__str__ = __str__
			new_type.__repr__ = __str__

			cls.__instances[t] = new_type
			return new_type

class Bin:
	"""Factory class to display an int in bin format"""

	__instances = {}

	@typecheck
	def __new__ (cls, t = int):
		if t == int:
			t = IntValue

		assert issubclass (t, IntValue)

		try:
			return cls.__instances[t]
		except KeyError:

			new_type = type (t.__name__, (t,), {})
			try:
				s = new_type._UnsignedBigEndianIntValue__size
			except AttributeError:
				def __str__ (self):
					return bin (self)
			else:
				def __str__ (self):
					return ("-0b" if self < 0 else "0b") + format (abs (self), self.__format)
				new_type.__format = "0%db" % s

			new_type.__str__ = __str__
			new_type.__repr__ = __str__

			cls.__instances[t] = new_type
			return new_type


