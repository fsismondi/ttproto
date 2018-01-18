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

import copy, functools, logging

from ttproto.core.typecheck import *
from ttproto.core.data import *
from ttproto.core.exceptions import Error
from ttproto.core.named import skip_parent_var_name
from ttproto.core import exceptions

#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('[packet module]')



__all__ = [
    'PacketValue',
    'PacketClass',
    'Optional',
]


class Optional:
    """Special class used to indicate that a field in a packet is optional"""

    @typecheck
    def __init__(self, type_: is_type):
        self.type = type_


class PacketValue(Value):
    """A class for representing data packets.

	A packet is a structured value containing multiple fields that are
	ordered, named and typed. The PacketValue class is typically used for
	representing protocol PDUs and their payload.

	PacketValue is an abstract class. The actual classes representing the
	PDUs are generated using the metaclass function PacketClass().

	A packet class may have multiple variants. This feature is typically
	used for protocols that define multiple kind of messages that share a
	common header.

	For instance the diagram below represents the inheritance tree for the
	ICMPv6 messages.

					 .-------.
					 | Value |
					 '-------'
					     ^
					     |
				      .-------------.
				      | PacketValue |
				      '-------------'
					     ^
					     |
			 .------------------------------------------.
			 |                  ICMPv6                  |
			 '------------------------------------------'
			      ^                 ^     ^     ^
			      |                 |     |     |
		      .------------.            |     |   .---------------------------.
		      | ICMPv6Echo |            |     |   | ICMPv6RouterAdvertisement |
		      '------------'            |     |   '---------------------------'
			^       ^               |     |
			|       |               |   .----------------------------.
	 .-------------------.  |               |   | ICMPv6NeighborSolicitation |
	 | ICMPv6EchoRequest |  |               |   '----------------------------'
	 '-------------------'  |               |
		      .-----------------.     .-----------------------------.
		      | ICMPv6EchoReply |     | ICMPv6NeighborAdvertisement |
		      '-----------------'     '-----------------------------'

	The ICMPv6 type is defined as a packet type containing 4 fields:
	 - Type		(UInt8)
	 - Code		(UInt8)
	 - Checksum	(UInt16)
	 - Body		(bytes)
	This definition is generic in the sense that it can represent any kind
	of ICMPv6 packet. However, the body onf the message is handled as a raw
	binary string, which is not convenient.

	The inheritance mechanisms of the PacketValue class allows defining
	specialised variants of the same type of message. For example, the
	ICMPv6NeighborSolicitation derives from the ICMPv6 types and has 7
	fields:
	 * Type		(UInt8)
	 * Code		(UInt8)
	 * Checksum	(UInt16)
	 - Flags	(UInt16)
	 - Reserverd	(UInt16)
	 - TargetAddress(IPv6Address)
	 - Options	(ICMPv6OptionList)
	The class inherits its first 3 fields (Type, Code & Checksum) from the
	base class ICMPv6, and defines 4 new fields in place of the binary body
	field.

	The inheritance is directly handled in the python type system. Thus we
	have the following equalities:
	  issubclass (ICMPv6NeighborSolicitation,   ICMPv6) == True
	  isinstance (ICMPv6NeighborSolicitation(), ICMPv6) == True
	  isinstance (ICMPv6(), ICMPv6NeighborSolicitation) == False

	NOTE: the latter case will always be False, even if semantically
	speaking the ICMPv6 value can be filled with an neighbour solicitation
	message (however, if well-formatted, NS messages will by default always
	be represented with the type ICMPv6Neighbor solicitation)

	Optional field
	--------------

	Some fields may not always be present in a message. Those can
	explicitely contain “no value” (which is different from containing the
	None value which indicates that the field is undefined)

	“no value” is represented with a special value class: Omit.

	When the type of a field is enclosed in the Optional class, this field
	can be indifferently field a value of this type or with the value Omit().

	For example a field containing an optional integer values will have its
	type set to “Optional(int)“.


	Default Values and tags
	-----------------------

	For each field a packet class may provide a default value.

	These default values are used when building messages. If the message is
	not fully defined (ie. some of its fields are equal to None), then the
	missing fields will be filled with their respective default value.

	Alternatively it if possible to provide a tag (inheriting from the
	PacketValue.Tag class) which can implement special processing:
	 - compute the default value of the field on a case-per-case basis
	 - making decisions when decoding a message
	For example the ttproto.core.inet.meta class provides the following tags:
	 - InetLength()		to represent the length of another field
	 - InetType()		to represent the type of another field
	 - InetVariant()	to represent the type of the current packet
	 - InetIPv6Checksum()	to compute the IPv6 checksum of a message


	The following example builds a message neighbour solicitation message
	encapsulated in an IPv6 header with all their fields left undefined
	(thus they are field with default values or automatically computed from
	a tag). The column on the right side (“default value or tag”) shows how
	the default values are defined in the class. It is not part of the
	actual output, but was added here to help understanding the process.

		>>> Message(IPv6()/ICMPv6NeighborSolicitation()).display()
		###[ IPv6 ]###					+-- default value or tag --
		  Version=                  6			| 6
		  TrafficClass=             0			| 0
		  FlowLabel=                0			| 0
		  PayloadLength=            24			| InetLength("Payload")
		  NextHeader=               58			| InetType("Payload", ...)
		  HopLimit=                 64			| 64
		  SourceAddress=            ::			| ::
		  DestinationAddress=       ::			| ::
		  Payload= 					|
		###[ ICMPv6NeighborSolicitation ]###		|
		    Type=                   135			| InetVariant(...)
		    Code=                   0			| 0
		    Checksum=               30893		| InetIPv6Checksum()
		    Reserved=               0			| 0
		    TargetAddress=          ::			| ::
		    Options= 					| []
		###[ ICMPv6OptionList ]###			+--------------------------
		Encoded as:
		    60 00 00 00 00 18 3a 40  00 00 00 00 00 00 00 00
		    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		    00 00 00 00 00 00 00 00  87 00 78 ad 00 00 00 00
		    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00

	In this example, most of the fields (Version, TrafficClass, FlowLabel,
	HopLimit, ...) just contain a default value which is copied into the
	message being built.

	Other fields have a tag indicating how to compute the default value:

	 - “PayloadLength” has the tag InetLength("Payload") which fills the
	   field with the length of the encoded payload (the neighbor
	   solicitation), whose actual length is 24 bytes.

	 - “NextHeader” has the tag InetType, which fills the field accordingly
	   to the type of the payload. In its internal dictionnary, the ICMPv6
	   type is associated to the value 58.

	 - “Type” has the tag InetVariant, which fills the field accordingly to
	   the type of the current packet (which is a variant of ICMPv6). In
	   its internal dictionnary, the ICMPv6NeighborSolicitation type is
	   associated to the value 135.

	 - “Checksum” has the tag InetIPv6Checksum(), which automatically
	   computes an IPv6 checksum from the content of the ICMPv6 messsage
	   and its enclosing IPv6 header.


	Similar processes can be implemented to customise the decoding of a
	packet, especially to make decisions for the decoder. Example:
	 - InetLength() tells what is the expected length of a field
	 - InetType() and InetVariant() tells what is the expected type of a
	   field (and thus which decoder shall be used in order to decode it
	   properly)


	TODO: Inheritance + flattening + match operations
	"""

    class Tag:
        """Base class for tags used to customise packet fields."""

        def __init__(self, default: optional(Value) = None):
            """Initialise the tag

			'default' is the default value to be used when the
			field is left undefined.
			"""
            self.__default = default

        def __repr__(self):
            return "%s(%s)" % (type(self).__name__, repr(self.__default))

        def get_default_value(self):
            """Return the default value for this field, or None if there is no default value"""
            return self.__default

        def build_message(self, value, ctx=None):
            """Build the content of the field

			This function is called by PacketValue._build_message()
			when it needs to encode the value of an individual
			field.

			'value' is the actual value of the field to be encoded.

			The default action is just to return value.build_message().


			This function may be reimplemented in order to do some
			further processing (eg. changing the presentation format, ...)

			'ctx' is meant to carry some information about the context
			in which this field is encoded. Its content is out of the
			scope of the present module. PacketValue._build_message()
			does not use it. (see ttproto.core.lib.inet.meta.InetPacketValue for
			an example of usage)
			"""
            return value.build_message()

        def decode_message(self, type_, bin_slice, ctx=None):
            """Decode the content of the field

			This function is called by PacketValue._decode_message()
			when it needs to decode the value of an individual
			field.

			'type_' is the expected type of the field.
			'bin_slice' is the slice containing the data to be decoded.

			The default action is just to return type_.decode_message(bin_slice).


			This function may be reimplemented in order to do some
			further processing (eg. changing the presentation format, ...)

			'ctx' is meant to carry some information about the context
			in which this field is encoded. Its content is out of the
			scope of the present module. PacketValue._build_message()
			does not use it. (see ttproto.core.lib.inet.meta.InetPacketValue for
			an example of usage)
			"""
            return type_.decode_message(bin_slice)

        @typecheck
        def init(self, parent: type, field_id: int, field):
            """Initialise the tag

			This function is called at the end of the constructor of
			PacketValue, once all the fields are defined.

			 - 'parent' is the PacketValue subclass that contains this field
			 - 'field_id' is the index of the field (starting from 0)
			 - 'field' is the PacketValue.Field instance representing the field
			"""
            assert parent.get_field(field_id) is field
            assert field.tag is self

            self.__packet_type = parent
            self.__field_id = field_id
            self.__field = field
            self.__default = self.__field.store_data(self.__default, none_is_allowed=True)

        def get_packet_type(self):
            """Get the PacketValue subclass that contain this field

			NOTE: this function cannot be used before init() is called.
			"""
            return self.__packet_type

        def get_field(self):
            """Get the PacketValue.Field instance representing the field
			this tag is attached to

			NOTE: this function cannot be used before init() is called.
			"""
            return self.__field

        def get_field_id(self):
            """Get the index of the field this tag is attached to

			NOTE: this function cannot be used before init() is called.
			"""
            return self.__field_id

    class Field:
        """A class representing a field in PacketValue subclasses

        A field has several attributes:
		 - name		the name of the field
		 - alias	a shortened alias for the field
		 - optional	boolean telling if the field is optional or not
		 - type		type of data that can be stored into this field
		 - tag		a tag holding a default value for the field and
		 		that can provide some special processing
		"""

        @typecheck
        def __init__(self, name: str, alias: str, typ: either(is_type, Optional), tag=None):
            """Constructor

			'typ' can be either a type (is_type()) or an instance of the Optional() class
			(to indicate that the field is optional). It is converted into a Value
			subclass using get_type()

			The 'tag' parameter can be a PacketValue.Tag class or anything else. In the
			latter case a PacketValue.Tag object is implicitely built, using this value
			as the default value of the field.
			"""

            self.name = name
            self.alias = alias
            self.optional = isinstance(typ, Optional)
            self.type = get_type(typ.type if self.optional else typ)
            if isinstance(tag, PacketValue.Tag):
                self.tag = tag
            else:
                self.tag = PacketValue.Tag(self.store_data(tag))

        def __repr__(self):
            fmt_type = "Optional(%s)" if self.optional else "%s"
            return "PacketValue.Field(%s, %s, %s, %s)" % (
                repr(self.name),
                repr(self.alias),
                fmt_type % repr(self.type),
                repr(self.tag)
            )

        @typecheck
        def store_data(self, data, none_is_allowed=True):
            """shortcut to store_data() using the Field's details (type, optional)"""

            return store_data(data, self.type, none_is_allowed=none_is_allowed, omit_is_allowed=self.optional)

    class ProxyList(list):
        """A list to ease datamanipulation prior to the construction of a PacketValue

		This class inherits from list and allows accessing its fields by their name.

		At initialisation, the list is associated with a PacketValue subclass. Then
		it is possible to use __getindex__ and __setindex__ with the
		name/alias of the field of the associated PacketValue class.

			Example:
			>>> l = PacketValue.ProxyList (IPv6)
			>>> l.append(6)		# version field
			>>> l.append(12)	# traffic class field
			>>> l.append(27)	# flow label field
			>>> l[0]
			6
			>>> l["Version"]
			6
			>>> l["tc"]
			12
			>>> l[1]
			12

		This list also allows setting up an input filter for the value
		stored into the list. By default data are stored as is. A conversion
		function can be to the constructor. This function is called each time
		an element is stored into the list, the return value of the function is
		stored in the list (in place of its input value). This can typically
		be used to implement some conversion mechanism (like calling store_data)

		The prototype of the conversion function is the following:
			def conversion_function (field: PacketValue.field, data)



		NOTE:	this class does not reimplement__delitem__(), insert(),
			pop(), remove() and sort()

		NOTE:	__getitem__ and __setitem__, when used to access a
			slice of data, do not support indexing by field name
		"""

        @typecheck
        def __init__(self, packet_type: type, convert_func: optional(callable) = None, value=None):
            def identity(field, data):
                return data

            self.set_type(packet_type)
            self.__func = convert_func if convert_func is not None else identity
            if value is not None:
                self.extend(value)

        def set_type(self, packet_type):
            assert issubclass(packet_type, PacketValue)
            self.__type = packet_type

        def get_type(self):
            return self.__type

        def clear(self):
            super()[:] = ()

        # reimplemented proxy functions
        @typecheck
        def __add__(self, other: list):
            result = copy.copy(self)
            result.extend(other)
            return result

        @typecheck
        def __iadd__(self, other: list):
            self.extend(other)
            return self

        def extend(self, other):
            for d in other:
                self.append(d)

        @typecheck
        def __imul__(self, nb: int):
            sample = copy.copy(self)
            self.clear()
            while nb > 0:
                nb -= 1
                self.extend(sample)
            return self

        def __mul__(self, nb: int):
            result = copy.copy(self)
            result *= nb
            return result

        def __rmul__(self, nb: int):
            return self * nb

        def __resolve_item(self, item: either(int, str, slice)):
            if item is None:
                return None
            elif isinstance(item, str):
                item = self.__type.get_field_id(item)
            elif isinstance(item, int):
                if item < 0:
                    item += len(self)
            else:
                assert isinstance(item, slice)
                item = slice(
                    self.__resolve_item(item.start),
                    self.__resolve_item(item.stop),
                    self.__resolve_item(item.step),
                )
            return item

        @typecheck
        def __getitem__(self, item: either(int, str, slice)):
            return super().__getitem__(self.__resolve_item(item))

        # TODO: doc warn about slices (no conversion)
        @typecheck
        def __setitem__(self, item: either(int, str, slice), value):
            item = self.__resolve_item(item)
            if isinstance(item, slice):
                return super().__setitem__(item, value)
            else:
                return super().__setitem__(item, self.__func(self.__type.get_field(item), value))

        def append(self, value):
            super().append(self.__func(self.__type.get_field(len(self)), value))

    @classmethod
    def List(cls, value=None):
        """Return a ProxyList associated to the current packet class"""
        return cls.ProxyList(cls, None, value)

    @classmethod
    def DataList(cls, value=None):
        """Return a ProxyList associated to the current packet class
		and that implement field input data conversion.

		This function is similar to .List() except that the returned list
		is initialised with a conversion that calls field.store_data()
		for each element stored into the list (thus implementing type
		conversion/initialisation for field values just like what is
		done in PacketValue's constructor.
		"""

        def store_func(field, data):
            return field.store_data(data)

        return cls.ProxyList(cls, store_func, value)

    ### class methods

    class __DescriptionProxy:
        @typecheck
        def __init__(self, func: callable):
            self.func = func

        def __getitem__(self, value):
            return self.func(value)

    @classmethod
    def metaclass_func(cls, name, bases, classdict,
                       fields: optional(list_of(tuple)) = None,
                       variant_of: optional(type) = None,
                       id: optional(int) = None,
                       prune: optional(int) = None,
                       descriptions: optional(dict_of(str, dict)) = {},
                       ):
        """Metaclass function for generating a PacketValue class.

		Parameters:

		 - fields	a list of tuples for the initialisation of the packet fields.
		 		Each tuple has the folowing content:
			 		(<name>, <alias>, <type>[, <tag_or_default_value>])

				'name' and 'alias' are string
				'type' is a core type (see is_type()) or an instance of the Optional class
				'tag'  is optional and may contain:
					- a default value
					- an instance of PacketValue.Tag (to implement special processing)

				see help (ttproto.core.packet.PacketValue.Field.__init__)

		- variant_of	Used for generating a packet class inheriting from another packet class.
		  (optional)	(thus implementing a specialised variant of the parent message). If it
		  		is not provided the new class will directly inherit from PacketValue.

				Example: ICMPv6NeighborAdvertisement can be defined as a variant_of ICMPv6

		- prune		When creating a variant of another packet, this field indicates how
		  (optional)	many fields defined in the parent class we want to keep in the new class.
		  		- If not provided, all the fields will be kept
				- If positive or zero, it indicates how many fields are kept
				- if negative (as usual in python indexing), the index will be taken
				  from the end of the list of fields. Thus, the number indicates how
				  many fields shall be removed.


				For example, the ICMPv6 message is roughly defined as follows.
					class ICMPv6 (
						metaclass = PacketClass,
						fields    = [
							("Type", 	"type",		UInt8),
							("Code",	"code",		UInt8),
							("Checksum",	"chk",		UInt16),
							("Body", 	"body",		bytes),
						]):
						pass
				This generic representation can handle any ICMPv6 message. Any
				message body can be represented since it is handled as a raw bytes
				string.

				However this format it not very convenient to manipulate (one must
				encode manually the message body. To overcome this, a specialised
				variant of packet can be derived from this class.

				Thus the neighbor solicitation message can be defined as:
					class ICMPv6NeighborSolicitation (
						metaclass  = PacketClass,
						variant_of = ICMPv6,
						prune      = -1,
						fields     = [
							("Reserved",		"rsv",	UInt32,		0),
							("TargetAddress",	"tgt",	IPv6Address,	"::"),
							("Options",		"opt",	ICMPv6OptionList, []),
						]):
					pass
				The 'prune' is set to -1 to indicate that we want to remove the last field
				of the original packet class ICMPv6 (the Body) field. Thus the resulting
				packet class ICMPv6NeighborSolicitation contains 6 fields:
				 - 3 fields inherited from the base ICMPv6 packet (Type, Code, Checksum)
				 - 3 new fields (Reserved, TargetAddress, Options)
				(also the original ICMPv6 class is not modified)

		- id		A value identifying this variant of packet
		  (optional)	Modular protocol messages typically have a “Type” which indicates which
				variant of the protocol message is present. This feature is essential
				for encoding and decoding the messages properly.

				Each hierarchy of packet classes (eg. ICMPv6 and its daughter classes)
				shares a common bi-dictionnary (of type BidictValueType) that associates
				each message variant with a value.

				This dictionnary can be accessed by adequate fields tags in order to
				encode and decode the message properly.

				See help(ttproto.core.lib.inet.meta.InetVariant) for an example.

		- descriptions	This argument may contain a dictionnary of objects providing textual
		  (optional)	descriptions in a per-field and per-value basis. This attribute	has no
				effects in the tests, its purpose is only to help understanding log
				reports.

				The object providing the description can be:
				 - a dictionnary (or any object providing __getitem__) mapping values
				   to textual descriptions
				 - a function (or any object providing __call) accepting a value as
				   parameter and returning a textual description (or None if the
				   function is unable to provide a description)

				For example, for ICMPv6 we can set a description to the 'Type' field:

				  - as a dictionnary:

					descriptions = {
					"Type": {
						1:	"Destination Unreachable",
						2:	"Packet Too Big",
					}}

				  - as a function:

				  	def icmpv6_type_description (value):
						if value == 1:
							return "Destination Unreachable"
						elif value == 2:
							return "Packet Too Big"
						else:
							return None
				  	...

					descriptions = { "Type": icmpv6_type_description }


				NOTE: when defining an inherited class (using “variant_of”) it
				if possible do overwrite the description dict for a field
				inherited from the parent class. This is especially useful when
				a common field has a different meaning in each variant of the
				message.
				For example the meaning of the “Code” field in ICMPv6 depends on
				the kind of message. Thus the ICMPv6DestinationUnreachable message
				can set:
					descriptions = {
					"Code": {
						0:	"No route to destination",
						1:	"Administratively prohibited",
						...
					}}
				without affecting the other ICMPv6 variants.
		"""

        assert len(bases) == 0  # FIXME: it could be useful to have multiple inheritance in some cases ?

        assert "variant_descriptions" not in classdict  # obsolete, use the descriptions meta-parameter instead

        if variant_of is None:
            # root class definition
            assert fields is not None
            assert prune is None

            result = type(name, (cls,), classdict)

            # initialise the dicts for resolving variant ids
            result.__cls_variants_bidict = BidictValueType(None, result)

            result.__cls_root_variant = result
            result.__cls_base_variant = None

        else:
            # variant class definition
            assert issubclass(variant_of, cls)  # FIXME: maybe too strict (subclass os PacketValue could be sufficient)

            result = type(name, (variant_of,), classdict)

            result.__cls_base_variant = variant_of

        result.__cls_variant = result
        result.__cls_variant_id = id

        if id is not None:
            assert id not in result.__cls_variants_bidict  # there should not be an existing variant with the same id

            result.__cls_variants_bidict[id] = result

        result.__init_fields(fields, prune)

        # copy the descriptions from the parent class (or initialise an empty list)
        d = variant_of.__cls_descriptions[0:result.__cls_prune] if variant_of else []
        missing = result.get_length() - len(d)
        if missing:
            d.extend([{} for v in range(0, missing)])

        # store the descriptions
        for field_name, desc_map in descriptions.items():
            i = result.get_field_id(field_name)
            # check that it provides the [] operator
            if not hasattr(desc_map, "__getitem__"):
                assert hasattr(desc_map, "__call__")  # description map must provide __getitem__ or __call__
                desc_map = cls.__DescriptionProxy(desc_map)

            # check that the dict contains only strings
            if hasattr(desc_map, "values"):
                for txt in desc_map.values():
                    assert isinstance(txt, str)
            d[i] = desc_map

        result.__cls_descriptions = d

        return result

    @classmethod
    @typecheck
    def __init_fields(cls, fields: optional(list_of(tuple)), prune: optional(int) = None):
        # check the validity of the fields
        if fields is not None:
            for f in fields:
                assert 3 <= len(f) <= 4
                assert type(f[0]) == str
                assert type(f[1]) == str
                assert is_type(f[2]) or isinstance(f[2], Optional)

        cls.__cls_payload_id = None

        if cls.__cls_base_variant is None:
            # root variant
            cls.__cls_prune = 0
            cls.__cls_fields = []
        else:
            # derived variant
            base_length = cls.__cls_base_variant.get_length()

            if prune is None:
                cls.__cls_prune = base_length
            else:
                assert -base_length <= prune <= base_length

                if prune < 0:
                    prune += base_length
                cls.__cls_prune = prune

            # keep the base payload id if not pruned
            base_pid = cls.__cls_base_variant.get_payload_id()

            if base_pid is not None and base_pid < cls.__cls_prune:
                cls.__cls_payload_id = base_pid

            # copy the fields from the base class
            cls.__cls_fields = cls.__cls_base_variant.__cls_fields[0:cls.__cls_prune]

        if fields:
            for f in fields:
                # ensure there is no name/alias collision in the field names
                for previous_field in cls.__cls_fields:
                    for name in f[0:2]:
                        assert name != previous_field.name
                        assert name != previous_field.alias

                if f[0] == "Payload":
                    assert cls.__cls_payload_id is None
                    cls.__cls_payload_id = len(cls.__cls_fields)

                cls.__cls_fields.append(PacketValue.Field(*f))

        # initialise the tags in the new fields
        i = cls.__cls_prune
        for f in cls.__cls_fields[cls.__cls_prune:]:
            f.tag.init(cls, i, f)
            i += 1

    @classmethod
    def get_length(cls):
        """Return the number of fields in this type of packet"""
        return len(cls.__cls_fields)

    @classmethod
    @typecheck
    def fields(cls) -> iterable:
        """Return an iterator on the fields of this packet (iterator
		of PacketValue.Field objects)"""

        return iter(cls.__cls_fields)

    @classmethod
    @typecheck
    def get_field(cls, id: either(int, str)) -> Field:
        """Access one individual Field either by name, alias or numerical index

		Raise exceptions.UnknownField in case the requested field does not exist
		"""
        if isinstance(id, str):
            id = cls.get_field_id(id)
        return cls.__cls_fields[id]

    @classmethod
    @typecheck
    def get_field_id(cls, arg: either(str, int)) -> int:
        """Get the numerical index of a field, given its name or numerical index

		Raise exceptions.UnknownField in case the requested field does not exist
		"""
        if isinstance(arg, int):
            assert -cls.get_length() <= arg < cls.get_length()
            return arg % cls.get_length()
        else:
            i = 0
            for f in cls.fields():
                if f.name == arg or f.alias == arg:
                    return i
                i += 1

        raise exceptions.UnknownField("Unknown field name", arg)

    @classmethod
    @typecheck
    def get_prune_id(cls) -> int:
        """Get the number of fields inherited from the parent packet class.

		If the class is not a variant of a base packet, the prune id is 0.
		"""
        return cls.__cls_prune

    @classmethod
    @typecheck
    def get_base_variant(cls) -> optional(type):
        """Return the base class for this variant of packet

		The base variant is the “variant_of” argument of PacketClass().
		It is equal to None in case the class does not inherit from
		another packet class.
		"""
        return cls.__cls_base_variant

    @classmethod
    @typecheck
    def get_root_variant(cls) -> type:
        """Return the root packet class hierarchy of PacketValue classes"""
        return cls.__cls_root_variant

    @classmethod
    def get_variants_bidict(cls) -> BidictValueType:
        """Access the bi-dictionnary that maps variant ids to variant types

		see help (PacketClass)
		"""
        # TODO: return a read-only proxy instead
        return cls.__cls_variants_bidict

    @classmethod
    @typecheck
    def get_payload_id(cls) -> optional(int):
        """Return the id of the "Payload" field.

		If there is no field named "Payload", the function just returns None.
		"""
        return cls.__cls_payload_id

    # TODO: refactor this in a cleaner way (eg. remove formats)
    @classmethod
    def get_variant_description(cls, variant_id) -> str:
        """Get a textual description of the given variant id"""

        field_id = cls.get_variant_field_id()
        txt = cls.get_description_for_value(field_id, variant_id) if field_id is not None else None

        if txt:
            return "%s %s" % (cls.get_root_variant().__name__, txt)
        elif variant_id in cls.__cls_variants_bidict:
            return cls.__cls_variants_bidict[variant_id].__name__
        elif variant_id is not None:
            return "%s Type %d" % (cls.get_root_variant().__name__, variant_id)
        else:
            return cls.get_root_variant().__name__

    @classmethod
    @typecheck
    def get_variant(cls):
        """Get the PacketValue variant of a given value.

		NOTE: the result is not necessary equal to cls (it will differ
		if cls is manually inherited from a packet class
		"""

        return cls.__cls_variant

    @classmethod
    @typecheck
    def get_variant_id(cls) -> optional(int):
        """Get the id of the variant of this class.

		The result is None if this class has no variant id set.
		"""
        return cls.__cls_variant_id

    @classmethod
    @typecheck
    def get_variant_type(cls, id: int) -> type:
        """variant id -> variant type resolution

		If the variant id is unknown, cls.get_root_variant() is
		returned. Thus this function always return a result.
		"""
        return cls.__cls_variants_bidict[id]

    @classmethod
    @typecheck
    def get_description_for_value(cls, field: either(str, int), value: is_value) -> optional(str):
        """Get the textual description for a given value in a given field

		If no description is set for this value, the function just returns None.
		"""
        try:
            return cls.__cls_descriptions[cls.get_field_id(field)][value]
        except KeyError:
            return None

    @staticmethod
    # FIXME: shall we keep this function ?
    def get_variant_field_id():
        """Return the id of the field that encodes the variant of this
		hierarchy of packet classes (or None if there is no such field)


		NOTE: the identification of the variant field id is out of the scope
		of the ttproto.core.packet module. The default implementation just returns
		None.
		"""
        return None

    ### instance methods

    @typecheck
    def __init__(self, *k, **kw):
        """Initialise a packet value.

		The function fills the content of the packet
		- either from a list of values (*k), in this case the values are expected
		  to have the same order as the
		- either by assigning the fields explicitely (**kw notation), in that case,
		  the fields are referenced by their name or alias. Unreferenced fields will
		  be left undefined.


		For example, using the ICMPv6 type definition above, the two following
		instantiations are equivalent:
			my_pkt = ICMPv6 (4, 0, 0x1234, b"   ")
			my_pkt = ICMPv6 (Type=4, Code=0, Checksum=0x1234, Body=b"   ")

		When using the explicit assignment notation, unreferenced fields are left
		undefined, thus the followings are equivalent:
			my_pkt2 = ICMPv6 (Type=4, Body=b"blah")
			my_pkt2 = ICMPv6 (4, None, None, b"blah")
			my_pkt2 = ICMPv6 (Type=4, Code=None, Checksum=None, Body=b"blah")
		"""

        Value.__init__(self)

        # TODO: copy constructor ?

        if len(k):
            if len(kw):
                raise Error('cannot mix positional and named arguments')

            missing = len(self) - len(k)
            if missing < 0:
                raise Error("to many parameters")

            self.__datas = [f.store_data(d) for d, f in zip(k, self.fields())]

            if missing:
                self.__datas.extend([None for v in range(0, missing)])
        else:
            # named parameters

            self.__datas = []
            for field in self.fields():
                for n in field.name, field.alias:
                    if n in kw:
                        v = kw.pop(n)
                        break
                else:
                    v = None

                # append the type to the internal list, but possibly convert it before
                self.__datas.append(field.store_data(v))

            if len(kw):
                raise Error('unknown fields in type %s: %s' % (type(self).__name__, ' '.join(kw.keys())))

    __len__ = get_length

    # TODO: clarify the semantics of __getitem__(type)
    @typecheck
    def __getitem__(self, index: either(int, str, is_type)) -> optional(is_data):
        """Access one field by id or name or by type (shortcut for find_type())

		The following indexing ways are supported:
		- positive or null integer
		- negative integer
		- field name
		- field alias

		Additionnaly, if a type is given as parameter, the function
		will return the result of find_type() (to look up this type
		recursively in the payload). If not found, it raises KeyError.
		"""
        if isinstance(index, str):
            index = self.get_field_id(index)
        elif isinstance(index, int):
            assert -len(self) <= index < len(self)

            if index < 0:
                index += len(self)
        else:
            assert issubclass(index, Value)
            assert self.is_flat()  # this makes things less complex (i don't think it will be necessary to support the general case)
            result = self.find_type(index)
            if result is None:
                raise KeyError
            return result

        return self.__datas[index]

    @typecheck
    def find_type(self: is_flat_value, type_: is_type) -> optional(Value):
        """Perform a recursive lookup in the payload of the packet to find a value of the requested type.

		If no value of this type is found, the function just returns None.

		Example:
			>>> Ieee802154(pl=SixLowpanIPHC(pl=IPv6(pl=UDP(pl="blah"))))
			Ieee802154(pl=SixLowpanIPHC(pl=IPv6(pl=UDP(pl='blah'))))
			>>> msg = Ieee802154(pl=SixLowpanIPHC(pl=IPv6(pl=UDP(pl="blah"))))
			>>> msg.find_type(UDP)
			UDP(pl='blah')
		"""

        pid = self.get_payload_id()
        if pid is not None:
            payload = self[pid]
            if payload is not None:
                type_ = get_type(type_)
                return payload if isinstance(payload, type_) else payload.find_type(type_)
        return None

    def __iter__(self):
        return iter(self.__datas)

    @skip_parent_var_name
    @typecheck
    def pack(self, data: is_data) -> this_class:
        """Encapsulate the given data into the present packet

		The given data is encapsulated into the "Payload" field (which
		must be present).

		If the current packet has no payload defined, this function is
		just returns self(Payload=data) (it generates a derived object
		and fills the Payload field with the given data.

		Otherwise the function will recursively call the pack() function
		on the existing payload. The result will be equal to:
			self(Payload=self["Payload"].pack(data))
		"""
        pid = self.get_payload_id()
        if pid is None:
            raise Error("Cannot pack a message into %s (no Payload field)" % type(self).__name__)

        new_seq = self()

        payloads = list(new_seq.get_datas(pid))
        field = new_seq.get_field(pid)
        if len(payloads) == 0:
            new_seq.__datas[pid] = field.store_data(data)
        elif len(payloads) >= 1:
            # FIXME: this will create lots of duplicated objects when pack is called in cascade using the __div__ operator
            #	 we may want to avoid duplicating the parent object when it is not modified
            #	 (in this case: when it is a truly anonymous object)

            # FIXME: if a sequence has multiple payloads (because of inheritance), we will
            #	 implicitely pack the data at the end of the first known payload
            #	 (this may have side effects ?)
            new_seq.__datas[pid] = field.store_data(payloads[0].pack(data))

        return new_seq

    @skip_parent_var_name
    def __truediv__(self, data):
        """Shortcut for the pack() method"""
        return self.pack(data)

    def _repr(self):
        result = []
        for field, data in zip(self.__cls_fields, self.__datas):
            if data is not None:
                result.append("%s=%s" % (field.alias, repr(data)))
        return "%s(%s)" % (type(self).__name__, ", ".join(result))

    @typecheck
    def _is_flat(self) -> bool:
        for v in self.__datas:
            if v is not None and not v.is_flat():
                return False
        return True

    @typecheck
    def get_datas(self, index: either(int, str)) -> iterable:
        """Returns an iterator on the various data defined for a given field.

		This function will examinate the current packet value and all its
		parents and yield the value of the field referenced by the
		'index' parameter if defined.

		Example:
			>>> msg = IPv6 (hl = Range (int, 0, 255))
			>>> msg2 = msg (hl = 64, nh = 58)
			>>> list(msg2.get_datas("hl"))
			[64, Range(IntValue, 0, 255)]
			>>> list(msg2.get_datas("nh"))
			[58]
			>>> list(msg2.get_datas("src"))
			[]
		"""
        seq = self
        index = self.get_field_id(index)
        while seq:
            v = seq.__datas[index]
            if v is not None:
                yield v
            seq = seq.get_parent()

    @classmethod
    @typecheck
    def _flatten(cls, seq_values: list_of(this_class)):
        # generate the new seq
        result = cls()
        for i in range(0, len(result)):
            candidates = []
            for v in seq_values:
                candidates.extend(v.get_datas(i))
            new_v = Data.flatten(*candidates)
            if new_v is not None:
                new_v.freeze()
            result.__datas[i] = new_v

        return result

    @typecheck
    def _match(self, value: this_class, mismatch_list: optional(list)) -> bool:

        assert value.is_flat()

        if value.get_variant() != self.get_variant():
            if mismatch_list is not None:
                mismatch_list.append(VariantMismatch(value, self))
            # TODO: should compare the n first field

            return False

        result = True
        i = 0
        for pattern in self.__datas:
            if pattern is not None:

                if not pattern.match(value.__datas[i], mismatch_list):
                    result = False
                    if mismatch_list is None:
                        # no need to continue
                        break
            i += 1
        return result

    def _display(self, indent, output):
        indent += 2
        import ttproto.core.list

        print("###[ %s ]###" % type(self).__name__, file=output)

        i = 0
        for f in self.fields():
            hdr = "%s%s= " % (' ' * indent, f.name)

            if f.name == "Payload":
                print(hdr,file=output)
                # TODO: display alternative payloads in a better way
                for p in self.get_datas(i):
                    p._display(indent, output)

            # FIXME: ugly hack -> do something more generic
            elif issubclass(f.type, ttproto.core.list.ListValue):
                print(hdr,file=output)
                for v in self.get_datas(i):
                    v._display(indent, output)
            else:
                datas = []
                for d in self.get_datas(i):
                    s = str(d)
                    if isinstance(d, Value):
                        desc = self.get_description_for_value(i, d)
                        if desc:
                            s = "%s (%s)" % (s, desc)
                    datas.append(s)

                print("%s%s%s" % (
                    hdr,
                    " " * (0 if len(hdr) >= 28 else 28 - len(hdr)),
                    " & ".join(datas),
                ), file=output)
            i += 1

    @typecheck
    def _fill_default_values(self: is_flat_value) -> list_of(Value):
        """Fill the undefined fields with a default value.

		This function returns a list contaning for each field:
		- the value of the field (if defined)
		- the default provided by the field tag (otherwise)
		"""
        values = []

        for f, v in zip(self.fields(), self):

            # fill the field value (and use the default if not specified)

            if v is None:
                v = f.tag.get_default_value()

                if v is None:
                    raise Error("field '%s' in '%s' must have a value" % (f.name, type(self).__name__))
                else:
                    v = f.store_data(v)
            values.append(v)

        return values

    @typecheck
    def _build_message(self) -> is_flatvalue_binary:
        """Default packet encoder

		This function fills all undefined fields with their respective
		default value, then encode these fields and concatenate them
		from left to right.
		"""

        values, bins = zip(*(f.tag.build_message(v) for v, f in zip(self._fill_default_values(), self.fields())))

        return type(self)(*values), concatenate(bins)

    @classmethod
    def _decode_message(cls, bin_slice):
        """Default packet decoder

		This function decodes the packet from left to right.
		"""

        # decode each field from left to right
        values = []


        try:
            for field in cls.fields():
                v, bin_slice = field.tag.decode_message(field.type, bin_slice)
                #log.debug('["Tag based decoder] Decoding field as: ' + str(field.type) + ' || vaue:' +str(v))
                values.append(v)
        except Exception as e:
            exceptions.push_location(e, cls, field.name)
            raise

        # create the packet
        return cls(*values), bin_slice

    def describe(self, desc):
        """Describe the packet

		desc is a MessageDescription object to be filled with the packet details.

		This function returns the description of the packet variant if
		available, otherwire it just returns  hte name of the packet
		type.

		This function always succeeds
		"""

        # TODO: maybe move this into InetPacketValue
        variant_fid = self.get_variant_field_id()
        value = None if variant_fid is None else self[variant_fid]
        desc.info = type(self).__name__ if value is None else self.get_variant_description(value)

        return True

    def describe_payload(self, desc):
        """Describe the payload of the packet if any

		desc is a MessageDescription object to be filled with the payload details.

		This function fails (returns False) if there is no payload or
		if payload.describe() fails.
		"""

        pid = self.get_payload_id()
        if pid is not None:
            pl = self[pid]
            if pl:
                return pl.describe(desc)
        return False

    def get_description(self, field_id):
        """Return the textual description of a field (if any).

		This function examines the value of the referenced field, and
		return the associated textual description if any. If there is
		no description for this value, the function just returns None.
		"""
        return self.get_description_for_value(field_id, self[field_id])


PacketClass = PacketValue.metaclass_func


@typecheck
def _diff_list_handler(pkt: PacketValue):
    i = 0
    for field, value in zip(pkt.fields(), pkt):
        yield field.alias, value, functools.partial(pkt.get_description_for_value, i)
        i += 1


DifferenceList.set_handler(PacketValue, _diff_list_handler)
