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

import copy

from	ttproto.core.typecheck	import *
from	ttproto.core.data	import *
from	ttproto.core		import exceptions

__all__ = [
	'ListValue',
	'ListClass',
	'OrderedListClass',
	'UnorderedListClass',
]


class ListValue (Value):
	"""A class for representing a list of data

	A list is a structured value containing zero or more elements that may
	or may not be ordered (this is decided when the list class is created).

	ListValue is an abstract class. The actual classes representing the
	PDUs are generated using the metaclass function OrderedListClass() or
	UnorderedListClass().
	"""

	## class methods
	@classmethod
	@typecheck
	def metaclass_func (cls, name, bases, classdict, content_type: is_type, is_ordered: bool):
		"""Metaclass function for generating a ListValue class.

		Parameters:

		- content_type	The type of the data that can be stored in the list.

		- is_ordered	Boolean telling if the list is ordered or not. This affects
				the behaviour of the _match() method.
		"""

		assert len (bases) == 0 # FIXME: it could be useful to have multiple inheritance in some cases ?

		result = type (name, (cls,), classdict)

		result.__cls_content_type = get_type (content_type)
		result.__cls_is_ordered   = is_ordered

		return result

	@classmethod
	def is_ordered (cls):
		"""Return true if the present list class is ordered"""
		return cls.__cls_is_ordered

	@classmethod
	def get_content_type (cls):
		"""Return the type of data this list can store"""
		return cls.__cls_content_type

	## instance methods

	@typecheck
	def __init__ (self, datas: optional(iterable) = ()):
		"""Initialise a list from a set of data"""
		Value.__init__ (self)

		self.__datas = [store_data (d, self.__cls_content_type, none_is_allowed = False) for d in datas]
		self.__parent_length = 0

	@typecheck
	#TODO: clarify this point (flattened equivalent)
	def set_parent (self, parent: this_class):
		self.__parent_length = len (parent)
		return super (ListValue, self).set_parent (parent)

	def __len__ (self):
		"""return the number of elements in the list"""
		return self.__parent_length + len (self.__datas)

	@typecheck
	def __getitem__ (self, index: either(int, type)) -> optional (is_data):
		"""Access one element in the list

		If 'index' is an int, it can be either positive or negative indexing.

		If 'index' is a type, the function returns self.find_type(index) or
		raise KeyError if not found.
		"""

		if isinstance (index, type):
			result = self.find_type (index)
			if result is None:
				raise KeyError
			return result
		else:
			assert -len (self) <= index < len (self)

			if index < 0:
				# -> convert into a positive index
				index = len (self) + index

			l = self
			while index < l.__parent_length:
				l = l.get_parent()

			return l.__datas[index - l.__parent_length]

	def find_type (self: is_flat_value, type_: is_type) -> optional(Value):
		"""Find the first element of a given type in the list.

		If no value of this type is found, the function just returns None.

		NOTE: There is no recursion.
		"""
		type_ = get_type (type_)
		for d in self.__datas:
			if isinstance (d, type_):
				return d
		# FIXME: shall we look recursively into each value ?
		return None


	def __iter__ (self):
		"""Return an iterator on the data contained in this list (without the inherited elements)"""
		#FIXME: this function is not consistent with __getitem__ (because of inheritance)
		return iter (self.__datas)

	def _repr (self):
		return "%s([%s])" % (type (self).__name__, ", ".join (repr(d) for d in self.__datas))

	@typecheck
	def _is_flat (self) -> bool:
		for v in self.__datas:
			if not is_flat_value (v):
				return False
		return True

	#TODO: clarify how inheritance is handled (this may not be the best choice)
	@typecheck
	def get_datas (self) -> iterable:
		"""Return an iterator on all the elements of the list (including the inherited elements)"""
		p = self.get_parent()
		if p:
			for d in p.get_datas():
				yield d

		for d in self.__datas:
			yield d

	@classmethod
	@typecheck
	def _flatten (cls, lst_values: list_of (this_class)):

		# FIXME: will not work if the next values in lst_values are not parents of this one
		return cls ([Data.flatten (v) for v in lst_values[0].get_datas()])


	@staticmethod
	@typecheck
	# NOTE: the content of 'values' and 'patterns' is altered by this function
	def __try_all_matches (values: list_of (is_value), patterns: list_of (is_data)):
#		assert len(values) == len(patterns)

		for i in range (0, len(values)):
			for j in range (0, len (patterns)):
				if patterns[j].match (values[i]):
					v = values.pop(i)
					p = patterns.pop(j)
					if ListValue.__try_all_matches (values, patterns):
						return True
					values.insert (i, v)
					patterns.insert (j, p)

		# if the lists are empty then it is a success
		return not (values or patterns)

	@typecheck
	def _match (self, value: this_class, mismatch_list: optional(list)) -> bool:

		if len (self) == len (value):
			result = True
		else:
			result = False

			if mismatch_list is not None:
				mismatch_list.append (LengthMismatch (value, self))
			else:
				# no need to continue
				return result

		if self.__cls_is_ordered:

			# Ordered list
			for value, pattern in zip (value.get_datas(), self.get_data()):
				if not pattern.match (value):
					result = False
					if mismatch_list is None:
						# no need to continue
						break

		else:
			# Unordered list

			# FIXME: computationally intensive -> O(n!)
			if not self.__try_all_matches (list (value.get_datas()), list(self.get_datas())):

				result = False

				if mismatch_list is not None:
					mismatch_list.append (ValueMismatch (value, self))
		return result


	def _display (self, indent, output):
		indent +=2

		output.write ("###[ %s ]###\n" % self.get_type().__name__)

		for f in self.get_datas():
			f._display (indent, output)

	@typecheck
	def _build_message (self: is_flat_value) -> is_flatvalue_binary:
		"""Default list encoder

		This function encodes the list elements and concatenate them
		from left to right.
		"""

		# TODO: we'll need to keep a reference to the original template ?
		if not self:
			# empty list
			return self, b""
		else:
			# non empty
			values, bins = zip(*[v.build_message () for v in self])

			bin_result = concatenate (bins)

			return type(self) (values), concatenate (bins)

	@classmethod
	def _decode_message (cls, bin_slice, count = None):
		"""Default list decoder

		This function decodes the list from left to right.
		"""

		values = []

		def decode_field():
			nonlocal bin_slice
			v, bin_slice = cls.get_content_type().decode_message (bin_slice)
			values.append (v)

		try:
			if count is not None:
				# decode exactly 'count' entries
				for i in range (count):
					decode_field()
			else:
				# decode until the end of the slice
				while bin_slice:
					decode_field()
		except Exception as e:
			exceptions.push_location (e, cls, str(len(values)))
			raise

		return cls (values), bin_slice

ListClass = ListValue.metaclass_func

def OrderedListClass (name, bases, classdict, content_type):
	"""Metaclass function for generating an ordered ListValue class.

	Parameters:
	- content_type	The type of the data that can be stored in the list.
	"""
	return ListClass (name, bases, classdict, content_type, True)

def UnorderedListClass (name, bases, classdict, content_type):
	"""Metaclass function for generating an unordered ListValue class.

	Parameters:
	- content_type	The type of the data that can be stored in the list.
	"""
	return ListClass (name, bases, classdict, content_type, False)


@typecheck
def _diff_list_handler (lst: ListValue):
	i=0
	for value in lst:
		yield str (i), value, None
		i+=1

DifferenceList.set_handler (ListValue, _diff_list_handler)


