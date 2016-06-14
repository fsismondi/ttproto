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

from	ttproto.core.typecheck	import *
from	ttproto.core.data	import *
from	ttproto.core.exceptions	import Error

__all__ = [
	'PrimitiveValue',
	'PrimitiveValueClass',
	'IntValue',
	'BytesValue',
	'StrValue',
	'BoolValue',
]


class PrimitiveValue (Value):
	__type_map = {} # maps:	  python primitive type -> PrimitiveValueClass

	@classmethod
	def new (cls, value):
		try:
			t = cls.__type_map[type (value)]
		except KeyError:
			raise Error ("Cannot build a PrimitiveValue from '%s' (not a known python primitive type)" % value)

		return t (value)

	def __init__ (self, value = None):
		Value.__init__ (self)

	def describe (self, desc):
		# it is useless to have 'BytesValue' or 'IntValue' as message info description
		return False

	@classmethod
	@typecheck
	def get_type_for_python_type (cls, python_type: type):
		try:
			return cls.__type_map[python_type]
		except KeyError:
			raise Error ("There is no know PrimitiveValue class to handle type '%s'" % python_type)

	@classmethod
	def __register_type (cls, python_type, pv_class):
		assert issubclass (pv_class, PrimitiveValue)
		assert issubclass (pv_class, python_type) or (pv_class.__name__, python_type == "BoolValue", bool)

		cls.__type_map[python_type] = pv_class

	def get_python_type(self):
		return self.__python_type

	def _is_flat (self):
		return True

	def _repr (self):
		result = self._python_repr()

		if self.get_parent():
			result = "%s(%s)" % (type (self).__name__, result)

		return result

	def _python_repr (self):
		return self.__python_type.__repr__ (self)

	@classmethod
	def _flatten (cls, values: list_of (this_class)):

		# ensure that all the values are equal
		v0 = values[0]
		for v in values[1:]:
			if v != v0:
				raise Error ("cannot flatten different values together " + str (values))

		return v0

	def _match (self, value: optional (is_flat_value), mismatch_list: optional (list) = None) -> bool:

		if self == value:
			return True

		if mismatch_list is not None:
			mismatch_list.append (ValueMismatch (value, self))

		return False

	def _display (self, indent, output):
		indent += 2
		print("###[ %s ]###" % type(self).__name__, file = output)
		hdr = "%sValue= " % (' ' * indent)
		print("%s%s%s" % (
			hdr,
			" "* (0 if len(hdr) >= 28 else 28-len(hdr)),
			self._python_repr(),
		), file = output)

	def _build_message (self):
		return self, bytes (self.__python_type.__str__ (self), "utf-8")


def PrimitiveValueClass (name, bases, classdict):

	assert len (bases) == 1
	assert isinstance (bases[0], type)
	assert not issubclass (bases[0], Value)

	python_type = bases[0]

	# store the primitive type
	classdict["_PrimitiveValue__python_type"] = python_type

	if python_type == bool:
		# bool cannot be subclassed --> use int instead
		bases = PrimitiveValue, int
	else:
		bases = PrimitiveValue, python_type

	new_cls = type (name, bases, classdict)

	# register the new class so that we can build an instance from a primitive value
	PrimitiveValue._PrimitiveValue__register_type (python_type, new_cls)
	return new_cls

class IntValue (int, metaclass = PrimitiveValueClass):
	pass

class BytesValue (bytes, metaclass = PrimitiveValueClass):

	def _build_message (self):
		return self, self

	@classmethod
	def _decode_message (cls, bin_slice):

		value = bin_slice.raw()
		if bin_slice.get_bit_length() % 8:
			# remove the trailing byte and leave it in the slice
			value = value[:-1]
		new_slice = bin_slice[len(value):]

		return value, new_slice

# Strings are encoded in the UTF-8 format by default
class StrValue (str, metaclass = PrimitiveValueClass):
	def _build_message (self):
		return self, bytes (self, "utf-8")

	@classmethod
	def _decode_message (cls, bin_slice):

		buff = bin_slice.raw()
		if bin_slice.get_bit_length() % 8:
			# remove the trailing byte and leave it in the slice
			buff = buff[:-1]
		new_slice = bin_slice[len(buff):]

		return str (buff, "utf-8"), new_slice

class BoolValue (bool, metaclass = PrimitiveValueClass):
	def __new__ (cls, value = False):
		return int.__new__(cls, bool (value))

	def _python_repr (self):
		return repr (bool (self))

	def _build_message (self):
		assert self in (0, 1)
		return self, ((b"\x80" if self else b"\0"), 1)

	@classmethod
	def _decode_message (cls, bin_slice):
		return bin_slice[0] & 128, bin_slice.shift_bits(1)


