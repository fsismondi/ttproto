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
# CoAP link format messages based on RFC 6690
#

import re

from	ttproto.core.data		import *
from	ttproto.core.typecheck	import *
from	ttproto.core.list		import ListValue
from	ttproto.core.primitive	import IntValue, StrValue
from	ttproto.core			import exceptions
from	ttproto.core.packet		import Optional


#__all__ = [
#	'CoAPLink',
#]

IntValue.build_string = lambda self: (self, str (self))
_re_int = re.compile ("([0-9]+)")
@classmethod
def decode_string_int (cls, s):
	mo = _re_int.match (s)
	if not mo:
		raise Exception ("not an integer")

	return IntValue (mo.group(1)), s[mo.end(1):]
IntValue.decode_string = decode_string_int

StrValue.build_string = lambda self: (self, self)
StrValue.decode_string = classmethod (lambda cls, s: (cls (s), ""))

#TODO: assert is_flat in build_string

class TextListValue (ListValue):
	@classmethod
	@typecheck
	def metaclass_func (cls, name, bases, classdict, content_type: is_type, is_ordered: bool, delimiter: str, prepend: bool, reg: optional (either (tuple, str))):
		result = ListValue.metaclass_func (name, bases, classdict, content_type, is_ordered)

		# bless it
		# TODO: make metaclass_func a static function
		assert len (result.__bases__) == 1
		result.__bases__ = cls,
		result.__cls_delimiter = delimiter
		result.__cls_prepend = prepend
		if isinstance (reg, str):
			result.__cls_reg = re.compile (reg)
		elif isinstance (reg, tuple):
			result.__cls_reg = re.compile (*reg)
		else:
			result.__cls_reg = None

		return result

	def build_string (self):
		if not self:
			return self, ""
		else:
			values, strs = zip (*[v.build_string() for v in self])

			return type (self) (values), (self.__cls_delimiter + self.__cls_delimiter.join (strs))

	@classmethod
	def decode_string (cls, s: str, count = None):

		assert count is None or count >= 0

		values = []
		delimiter = cls.__cls_delimiter
		reg       = cls.__cls_reg
		prepend   = cls.__cls_prepend

		try:
			if count is not None:
				do_it = count > 0
			elif not s:
				do_it = False
			elif prepend:
				do_it = s.startswith (delimiter)
			elif reg:
				do_it = reg.match (s)
			else:
				do_it = True

			if do_it:
				if prepend:
					s = eat (s, delimiter)

				if reg:
					mo = reg.match (s)
					if not mo and prepend:
						raise Exception ("expected regex %r" % mo.pattern)
				while True:
					if reg:
						v, remainder = cls.get_content_type().decode_string (mo.group(0))
						if remainder:
							raise Exception ("unexpected %r" % remainder)

						s = s[mo.end(0):]
					else:
						v, s = cls.get_content_type().decode_string (s)
					values.append (v)

					if count is None:
						if not s or not s.startswith (delimiter):
							break
					else:
						count -= 1
						if not count:
							break

					s = eat (s, delimiter)

					if reg:
						mo = reg.match (s)
						if not mo:
							if count is None and not delimiter:
								break
							raise Exception ("expected regex %r" % mo.pattern)


		except Exception as e:
			exceptions.push_location (e, cls, str (len (values)))
			raise

		return cls (values), s

def TextOrderedListClass (name, bases, classdict, content_type, delimiter = "", prepend = False, reg = None):
	return TextListValue.metaclass_func (name, bases, classdict, content_type, True, delimiter, prepend, reg)

# TODO: merge it with Packet
# TODO: replace Packet.__init__(*k) with Packet.__init__(k)
# TODO: make TextRecord(s) an alias to TextRecord.decode_string(s)
class TextRecordValue (Value):
	class Tag:
		def __init__ (self, default: optional (Value) = None):
			"""Initialise the tag

			'default' is the default value to be used when the
			field is left undefined.
			"""
			self.__default = default

		def __repr__ (self):
			return "%s(%s)" % (type (self).__name__, repr (self.__default))

		def get_default_value (self):
			"""Return the default value for this field, or None if there is no default value"""
			return self.__default

		def build_string (self, value, ctx = None):
			return value.build_string()

		def decode_string (self, type_, s, ctx = None):
			return type_.decode_string (s)

		@typecheck
		def init (self, parent: type, field_id: int, field):
			assert parent.get_field (field_id) is field
			assert field.tag is self

			self.__parent_type = parent
			self.__field_id = field_id
			self.__field = field
			self.__default = self.__field.store_data (self.__default, none_is_allowed = True)

		def get_parent_type (self):
			return self.__parent_type

		def get_field (self):
			return self.__field

		def get_field_id (self):
			return self.__field_id

	class Field:
		@typecheck
		def __init__ (self, name: str, alias: str, typ: either (is_type, Optional), tag = None):

			self.name = name
			self.alias = alias
			self.optional = isinstance (typ, Optional)
			self.type = get_type (typ.type if self.optional else typ)
			if isinstance (tag, TextRecordValue.Tag):
				self.tag = tag
			else:
				self.tag = TextRecordValue.Tag (self.store_data (tag))

		def __repr__ (self):
			fmt_type = "Optional(%s)" if self.optional else "%s"
			return "TextRecordValue.Field(%s, %s, %s, %s)" % (
				repr (self.name),
				repr (self.alias),
				fmt_type % repr (self.type),
				repr (self.tag)
			)

		@typecheck
		def store_data (self, data, none_is_allowed = True):
			"""shortcut to store_data() using the Field's details (type, optional)"""

			return store_data (data, self.type, none_is_allowed = none_is_allowed, omit_is_allowed = self.optional)

		def decode_string (self, s, ctx = None):
			return self.tag.decode_string (self.type, s, ctx)

	@classmethod
	@typecheck
	def __init_fields (cls, fields: optional (list_of (tuple))):
		# check the validity of the fields
		if fields is not None:
			for f in fields:
				assert 3 <= len(f) <= 4
				assert type (f[0]) == str
				assert type (f[1]) == str
				assert is_type (f[2]) or isinstance (f[2], Optional)

		cls.__cls_fields = []

		if fields:
			for f in fields:
				# ensure there is no name/alias collision in the field names
				for previous_field in cls.__cls_fields:
					for name in f[0:2]:
						assert name != previous_field.name
						assert name != previous_field.alias

				cls.__cls_fields.append (TextRecordValue.Field (*f))

		# initialise the tags in the new fields
		i = 0
		for f in cls.__cls_fields:
			f.tag.init (cls, i, f)
			i+=1

	@classmethod
	def metaclass_func (cls, name, bases, classdict,
				fields:	list_of (tuple),
				format: optional (str) = None
				):
		assert len (bases) == 0 # FIXME: it could be useful to have multiple inheritance in some cases ?


		result = type (name, (cls,), classdict)

		result.__init_fields (fields)
		result.__cls_format = format

		if format is not None:
			assert format.count ("#") % 2 == 0

			elems = []
			is_field = False
			for e in format.split ("#"):
				if is_field:
					is_field = False
					if e:
						# field reference
						elems.append (result.get_field_id (e))
						is_field = False
						continue
					else:
						# "##" escape string
						e = "#"
				else:
					is_field = True

				if not e:
					continue

				# append e to the elems
				if elems:
					# stick it to the previous one (if any)
					if isinstance (elems[-1], str):
						elems[-1] += e
						continue

				elems.append (e)
			result.__cls_elems = elems

		return result

	@classmethod
	@typecheck
	def get_field (cls, id: either (int, str)) -> Field:
		"""Access one individual Field either by name, alias or numerical index

		Raise exceptions.UnknownField in case the requested field does not exist
		"""
		if isinstance (id, str):
			id = cls.get_field_id (id)
		return cls.__cls_fields[id]

	@classmethod
	@typecheck
	def get_field_id (cls, arg: either(str, int)) -> int:
		"""Get the numerical index of a field, given its name or numerical index

		Raise exceptions.UnknownField in case the requested field does not exist
		"""
		if isinstance (arg, int):
			assert -cls.get_length() <= arg < cls.get_length()
			return arg % cls.get_length()
		else:
			i=0
			for f in cls.fields():
				if f.name == arg or f.alias == arg:
					return i
				i+=1

		raise exceptions.UnknownField("Unknown field name", arg)

	@typecheck
	def __getitem__ (self, index: either (int, str)) -> optional (is_data):
		"""Access one field by id or name or by type (shortcut for find_type())

		The following indexing ways are supported:
		- positive or null integer
		- negative integer
		- field name
		- field alias
		"""
		if isinstance (index, str):
			index = self.get_field_id (index)
		else:
			# int
			assert -len (self) <= index < len (self)

			if index < 0:
				index += len (self)

		return self.__datas[index]

	@typecheck
	def __init__ (self, *k, **kw):

		super().__init__()

		# TODO: copy constructor ?

		if len(k):
			if len (kw):
				raise Error ('cannot mix positional and named arguments')

			missing = len (self) - len (k)
			if missing < 0:
				raise Error ("to many parameters")

			self.__datas = [f.store_data (d) for d,f in zip (k, self.fields())]

			if missing:
				self.__datas.extend([None for v in range (0, missing)])
		else:
			# named parameters

			self.__datas = []
			for field in self.fields():
				for n in field.name, field.alias:
					if n in kw:
						v = kw.pop (n)
						break
				else:
					v = None

				# append the type to the internal list, but possibly convert it before
				self.__datas.append (field.store_data (v))

			if len (kw):
				raise Error ('unknown fields in type %s: %s' % (type(self).__name__, ' '.join (kw.keys())))

	@classmethod
	def get_length (cls):
		return len (cls.__cls_fields)

	@classmethod
	@typecheck
	def fields (cls) -> iterable:
		return iter (cls.__cls_fields)

	__len__ = get_length

	def _repr (self):
		result = []
		for field, data in zip (self.__cls_fields, self.__datas):
			if data is not None:
				result.append ("%s=%s" % (field.alias, repr (data)))
		return "%s(%s)" % (type (self).__name__, ", ".join (result))

	def build_string (self):
		#TODO assert is flat
		#TODO support tags
		#TODO what to do with None fields

		values = []
		strs = []
		for d in self.__datas:
			if d is None:
				v, s = None, None
			else:
				v, s = d.build_string()
			values.append (v)
			strs.append (s)

		return type (self) (*values), "".join (
			(e if isinstance (e, str) else strs[e])  for e in self.__cls_elems
		)
	@classmethod
	def decode_string (cls, s):
		#TODO support tags

		values = [None]*cls.get_length()

		for e in cls.__cls_elems:
			if isinstance (e, str):
				if not s.startswith (e):
					raise Exception ("Expected %r" % e)
				s = s[len(e):]
			else:
				values[e], s = cls.get_field(e).decode_string(s)
		#TODO: exception location
		return cls (*values), s


	def _is_flat (self):
		#TODO
		return True

	@typecheck
	def get_datas (self, index: either (int, str)) -> iterable:
		seq = self
		index = self.get_field_id (index)
		while seq:
			v = seq.__datas [index]
			if v is not None:
				yield v
			seq = seq.get_parent()


	def _display (self, indent, output):
		indent +=2
		import ttproto.core.list

		print("###[ %s ]###" % type(self).__name__, file = output)

		i=0
		for f in self.fields():
			hdr = "%s%s= " % (' ' * indent, f.name)

			#FIXME: ugly hack -> do something more generic
			if issubclass (f.type, core.list.ListValue):
				print (hdr,file=output)
				for v in self.get_datas (i):
					v._display (indent, output)
			else:
				datas = []
				for d in self.get_datas (i):
					s = str (d)
					datas.append (s)

				print("%s%s%s" % (
					hdr,
					" " * (0 if len (hdr) >= 28 else 28-len(hdr)),
					" & ".join(datas),
				), file = output)
			i+=1

TextRecordClass = TextRecordValue.metaclass_func

class Reg (TextRecordValue.Tag):
	def __init__ (self, pattern, flags = 0):
		super().__init__()
		self.__pattern = pattern
		self.__re = re.compile (pattern, flags)

	# TODO: validate the strings we send

	def decode_string (self, type_, s, ctx = None):
		mo = self.__re.match (s)
		if not mo:
			raise Exception ("expected string matching regex %r" % self.__pattern)

		# number of groups in the regex
		n = len (mo.regs) - 1

		assert n <= 2 # must not have more than 2 () groups

		v, remainder = type_.decode_string (mo.group (n))
		if remainder:
			raise Exception ("unexpected: %r" % remainder)

		s = s[mo.end (1 if n == 2 else 0):]

		return v, s

_SCHEME = "([A-Z](?:[A-Z][0-9])*):"

def eat (s, token):
	if s.startswith (token):
		return s[len(token):]
	else:
		raise Exception ("expected %r" % token)

class CoAPLinkParam (
	metaclass = TextRecordClass,
	fields    = [
		("Name",	"name",		str),
		("Value",	"val",		str),
	]):

	__quoted = "anchor", "title"
	__unquoted = "hrefland sz title*".split()

	__re_tokens = re.compile(r"[]!#$%&'()*+./0-9:<=>?@a-z[^_`{|}~-]+", re.I)
	__re_parmname = re.compile (r"([a-zA-Z0-9!#$&+.^_`|~-]+|title\*)=")

	@classmethod
	def str_must_be_quoted (cls, s):
		mo = cls.__re_tokens.match (s)
		return not mo or mo.end(0) != len (s)

	@classmethod
	def param_must_be_quoted (cls, name):
		return name in cls.__quoted

	@classmethod
	def param_must_not_be_quoted (cls, name):
		return name in cls.__unquoted

	def build_string (self):
		name = self["name"]
		val = self["val"]

		if self.param_must_be_quoted (name):
			quote = True

		elif self.str_must_be_quoted (val):
			quote = True

			if self.param_must_not_be_quoted (name):
				raise Exception ("Param value contains invalid tokens (needs quoting)")

		else:
			quote = False

		if quote:
			val = '"%s"' % val.replace ('"', '\\"').replace ("\\", "\\\\")

		return self, "%s=%s" % (name, val)

	@classmethod
	def decode_string (cls, s):
		mo = cls.__re_parmname.match (s)
		if not mo:
			raise Exception ("invalid parameter name")

		name = mo.group(1)
		s = s[mo.end(0):]

		quoted = s and s[0] == '"'

		if quoted:
			if cls.param_must_not_be_quoted (name):
				raise Exception ("parameter %s must not be quoted" % name)

			val = []
			i = 1
			quote = False
			while i < len(s):
				c = s[i]
				if quote:
					quote = False
					if c == '\"' or c == '\\':
						val.append (c)
					else:
						# was an unquoted \
						val.append ("\\" + c)
				else:
					if c == '\\':
						quote = True
					elif c == '"':
						# end of string
						break
					else:
						val.append (c)
				i += 1
			else:
				raise Exception ("malformatted quoted string")

			val = "".join(val)
			s = s[i+1:]
		else:
			if cls.param_must_be_quoted (name):
				raise Exception ("parameter %s must be quoted" % name)

			mo = cls.__re_tokens.match (s)
			if not mo:
				raise Exception ("malformatted parameter value")

			val = mo.group(0)
			s = s[mo.end(0):]

		return cls (name, val), s







class CoAPLinkParamList (
	metaclass = TextOrderedListClass,
	content_type = CoAPLinkParam,
	delimiter = ";",
	prepend = True,
	reg = "[^;,]*",
):
	pass

class CoAPLinkValue (
	metaclass = TextRecordClass,
	fields    = [
		("UriReference",	"uri",	str, 	Reg("[^>]*")),
		("params",		"par",	CoAPLinkParamList),
	],
	format    = "<#uri#>#par#",
	):
	pass

class CoAPLink (
	metaclass = TextOrderedListClass,
	content_type = CoAPLinkValue,
	delimiter = ",",
):

	@classmethod
	def _decode_message (cls, bin_slice):

		if bin_slice.get_bit_length() % 8:
			raise Exception("Textual message length must be a multiple of 8 bits")

		s = str (bin_slice.raw(), "utf-8")

		v, s = cls.decode_string (s)

		if s:
			raise Exception ("String not fully decoded (%d bytes) left" % len(s))

		return v, bin_slice.shift_bits (bin_slice.get_bit_length())

	@typecheck
	def _build_message (self: is_flat_value) -> is_flatvalue_binary:

		v, s = self.build_string()

		return v, bytes (s, "utf-8")

