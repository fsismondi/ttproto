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

"""Data Representation module

This module contains the core classes and function for manipulating test data
in ttproto. This moudule provides commodity functions for:
 - generating messages
 - matching a received message with some expected pattern
 - encoding/decoding messages

All data manipulated for these purposes derive from the root class Data. There
are two variants of data: values and templates. Values are used to represent an
actual value (eg. an integer, an IPv6 packet, ...) and templates are used to
represent a pattern of values (eg. Range(int, 0, 15) means “any integer between
0 and 15”).

The figure below is a partial representation of the hierarchy of classes
deriving from Data.

                                           .------.
                            .------------->| Data |<-------.
                            |              '------'        |
                            |                              |
                        .-------.                    .----------.
           .----------->| Value |<-----.             | Template |<----.
           |            '-------'      |             '----------'     |
           |                           |                ^     ^       |
           |                           |                |     |       |
           |                           |                |     |       |
  .----------------.            .-------------.    .-------.  |       |
  | PrimitiveValue |            | PacketValue |    | Range |  |       |
  '----------------'            '-------------'    '-------'  |       |
    ^              ^                ^       ^           .-----------. |
    | .-------.    | .-----.        |       |           | ValueList | |
    | | bytes |    | | int |    .------. .-----.        '-----------' |
    | '-------'    | '-----'    | IPv6 | | UDP |                      |
    |    ^         |    ^       '------' '-----'               .-------------.
    |    |         |    |                                      | IPv6Prefix  |
 .------------. .----------.                                   '-------------'
 | BytesValue | | IntValue |
 '------------' '----------'
        ^
        |
 .-------------.
 | IPv6Address |
 '-------------'


Primitive values are handled in python with a set of predefined classes (int,
str, bytes, float, ...). For consistency purpose, ttproto provides a subclass for
each of these types that derives on Value (IntValue, StrValue, BytesValue). Most
classes and functions will perform the conversion on the fly using as_data() or
store_data(), thus it is not necessary to instantiate instances of these classes
directly. For example the following instances of the Range class will be
equivalent:
    Range (int, 0, 15)
    Range (IntValue, IntValue(0), IntValue(15))

Data objects are immutable (FIXME: to be confirmed). Once they are created,
their content cannot be modified.

Each Data object is associted to a type, which in the terminology of ttproto is a
subclass of Value. For an instance of a class derived from Value, get_type()
will return type(obj). An instance of a template will return the type used at
initialisation time. For example: Range(int, 0, 15).get_type() == IntValue.

Structured values (eg: PacketValue, ListValue) will store a separate Data object
for each of their fields. These fields can contain templates too.

Each Data object can be derived from another Data object. The resulting object
will be a combination of the parent object and of the child object. Deriving an
object is done by calling the function operator ( ).

For example:
    # an IPv6 header sent by 2001:db8::1
    #
    IPv6_src_A = IPv6 (src="2001:db8::1")

    # an IPv6 header multicasted by A
    #
    # (note that IPv6Prefix is a template for the type IPv6Address
    #  this one match all addresses starting with "ff")
    IPv6_multicast_from_A = IPv6_src_A (dst = IPv6Prefix ("ff00::/8"))

    # an IPv6 header sent by A to all nodes on the link
    #
    IPv6_A_to_all_nodes = IPv6_multicast_from_A (dst = "ff02::1")


This example will create a hierarchy of IPv6 value instances. Each of them
adding some information about what we want to have in our IPv6 header.

                                  .------------------------------------.
                                  |             IPv6_src_A             |
                                  | type: IPv6                         |
                                  |                                    |
                                  | fields: {                          |
                                  |   src: IPv6Address ("2001:db8::1") |
                                  | }                                  |
                                  '------------------------------------'
                     .------------------------------------.  ^
                     |       IPv6_multicast_from_A        | /
                     | type:   IPv6                       |/
                     | parent: IPv6_src_A                 |
                     |                                    |
                     | fields: {                          |
                     |   dst: IPv6Prefix ("ff::/8")       |
                     | }                                  |
                     '------------------------------------'
.------------------------------------.  ^
|        IPv6_A_to_all_nodes         | /
| type:   IPv6                       |/
| parent: IPv6_multicast_from_A      |
|                                    |
| fields: {                          |
|   dst: IPv6Address ("ff02::1")     |
| }                                  |
'------------------------------------'

Now these data can be used for several purposes, especially:
 - matching incoming messages
 - generating output messages

In case we want to match an incoming message from A sent to the all-nodes
multicast address, we can use the value IPv6_A_to_all_nodes. The match() method
will check that the given message matches all of the fields of
IPv6_A_to_all_nodes and of its parent values (IPv6_multicast_from_A and
IPv6_src_A).

Examples:
    >>> IPv6_A_to_all_nodes.match(IPv6(src="2001:db8::1", dst="ff02::1"))
    True
    >>> IPv6_A_to_all_nodes.match(IPv6(src="2001:db8::2", dst="ff02::1"))
    False
    >>> IPv6_A_to_all_nodes.match(IPv6(src="2001:db8::1", dst="ff02::2"))
    False

The second pattern IPv6_multicast_from_A may seem superfluous here because it
the third pattern IPv6_A_to_all_nodes is more strict. However it will be useful
because ttproto will be able to report which pattern in the hierarchy did or did not
match. For example:
    Match result
    - IPv6_from_A        -> success
    - IPv6_multicast_from_A    -> success
    - IPv6_A_to_all_nodes    -> failure
      * DestinationAddress: ValueMismatch: expected ff02::1 (got ff02::5)

Thus, with a quick look at the name of the patterns, it is easy to learn that it
is a multicast message sent by A but that it was not sent to all nodes. This
information will be useful later to interpret the test results in case of a
fail: with a quick look it is possible to know what did not match and whether it
is related to the test purpose or not.

It is possible to generate a data whose content is incompatible with its
parents. For example:
    >>> IPv6_multicast_from_A(dst="2001:db8::2")
    IPv6(dst='2001:db8::2').set_parent(IPv6(dst=IPv6Prefix('ff00::/8')).set_parent(IPv6(src='2001:db8::1')))

However such a data will not be useful in practice. If it is used for matching
another data, then the match will always fail (because the same destination
address cannot match 2001:db8::2 and ff00::/8). It will not be possible to
flatten the value (see below) and generate a message from this data.


Flat Values
-----------

It is possible to mix values and templates and to have multiple values for the
same field (because of inheritance). But in order to generate and exchange real
messages, we must have a unique unambiguous value. This kind of value are called
« Flat Values ». To be considered flat, a values fulfill the following
conditions:
    - it must not contain any template
    - it must not be derived from another data
    - in case of structured values, all its fields must either contain flat
      values or be undefined

Values can be collapsed into a flat value by calling the flatten() method. It
will return a new Value object with the same content, but flattened:

    >>> IPv6_A_to_all_nodes
    IPv6(dst='ff02::1').set_parent(IPv6(dst=IPv6Prefix('ff00::/8')).set_parent(IPv6(src='2001:db8::1')))

    >>> IPv6_A_to_all_nodes.flatten()
    IPv6(src='2001:db8::1', dst='ff02::1')

All values cannot be flattened. The operation will fail if a value does not
match other values or templates set for the same field.

    >>> IPv6_multicast_from_A(dst="2001:db8::2").flatten()
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/abaire/git/ttproto/core/data.py", line 656, in flatten
        result = value_class._flatten (values)
      File "/home/abaire/git/ttproto/core/packet.py", line 547, in _flatten
        new_v = Data.flatten (*candidates)
      File "/home/abaire/git/ttproto/core/data.py", line 661, in flatten
        raise exceptions.Error ("flattened value does not comply with one of its templates")
    core.exceptions.Error: Error: flattened value does not comply with one of its templates


Messages
--------

Messages are the basic unit exchanged between entities in the test. A message
has a value representation (which is flat and fully defined) and a binary
representation.

There are two ways to build a message:
- from a value : in this case, the constructor of Message will flatten the value
  and call the method build_message() to generate the message. This functions
  perform several interesting operations:
   * it fills undefined fields with a default value or for some special cases
   (checksum, type, length) it computes a value on the fly
   * it encodes the message into its binary format

    >>> Message(UInt16(66)).display()
    ###[ UInt16 ]###
      Value=                    66
    Encoded as:
        00 42

    >>> Message(IPv6(src="2001:db8:1::1", dst="2001:db8:2::1")/UDP(sport=1025, dport=427)/"blah blah").display()
    ###[ IPv6 ]###
      Version=                  6
      TrafficClass=             0
      FlowLabel=                0
      PayloadLength=            17
      NextHeader=               17
      HopLimit=                 64
      SourceAddress=            2001:db8:1::1
      DestinationAddress=       2001:db8:2::1
      Payload=
    ###[ UDP ]###
        SourcePort=             1025
        DestinationPort=        427
        Length=                 17
        Checksum=               58896
        Payload=
    ###[ StrValue ]###
          Value=                'blah blah'
    Encoded as:
        60 00 00 00 00 11 11 40  20 01 0d b8 00 01 00 00
        00 00 00 00 00 00 00 01  20 01 0d b8 00 02 00 00
        00 00 00 00 00 00 00 01  04 01 01 ab 00 11 e6 10
        62 6c 61 68 20 62 6c 61  68

- from a binary string and a type : in this case, the constructor of Message
  will call decode_message() on the expected type to decode the binary string
  and generate the associated value

    >>> Message (b"\0\x42", UInt16).display()
    ###[ UInt16 ]###
      Value=                    66
    Encoded as:
        00 42

    >>> Message(b'`\x00\x00\x00\x00\x11\x11@ \x01\r\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x01\x01\xab\x00\x11\xe6\x10blah blah', IPv6).display()
    ###[ IPv6 ]###
      Version=                  6
      TrafficClass=             0
      FlowLabel=                0
      PayloadLength=            17
      NextHeader=               17
      HopLimit=                 64
      SourceAddress=            2001:db8:1::1
      DestinationAddress=       2001:db8:2::1
      Payload=
    ###[ UDP ]###
        SourcePort=             1025
        DestinationPort=        427
        Length=                 17
        Checksum=               58896
        Payload=
    ###[ BytesValue ]###
          Value=                b'blah blah'
    Encoded as:
        60 00 00 00 00 11 11 40  20 01 0d b8 00 01 00 00
        00 00 00 00 00 00 00 01  20 01 0d b8 00 02 00 00
        00 00 00 00 00 00 00 01  04 01 01 ab 00 11 e6 10
        62 6c 61 68 20 62 6c 61  68

"""

from contextlib import contextmanager
import re, sys

from ttproto.core.typecheck import typecheck, optional, iterable, this_class, either, with_attr
from ttproto.core import named, exceptions

__all__ = [
    'is_type',
    'is_data',
    'is_value',
    'is_flat_value',
    'is_binary',
    'get_binary_length',
    'is_flatvalue_binslice',
    'is_flatvalue_binary',
    'concatenate',
    'get_type',
    'BinarySlice',
    'Data',
    'as_data',
    'store_data',
    'pack',
    'Value',
    'Omit',
    'Template',
    'Mismatch',
    'ValueMismatch',
    'TypeMismatch',
    'VariantMismatch',
    'LengthMismatch',
    'TemplateMismatch',
    'Message',
    'MessageDescription',
    'Bidict',
    'BidictValueType',
    'DifferenceList',
]

__known_primitive_types = int, str, bytes, bool


def is_type(arg):
    """Return True if the argument is a subclass of Value or if it is one of
    the known primitive types: int, str, bytes and bool (the types that can
    be mapped to one class deriving from PrimitiveValue)
    """
    return (isinstance(arg, type) and (issubclass(arg, Value))) or arg in __known_primitive_types


def is_data(arg):
    """Return True if the argument is an instance of the Data class or of
    one of the known primitive types (see is_type())
    """
    return isinstance(arg, Data) or type(arg) in __known_primitive_types


def is_value(arg):
    """Return True if the argument is an instance of the Value class or of
    one of the known primitive types (see is_type())
    """
    return isinstance(arg, Value) or type(arg) in __known_primitive_types


def is_flat_value(arg):
    """Return True if the argument is an instance of the Value class or of
    one of the known primitive types (see is_type()) and if it is flat
    """
    if isinstance(arg, Value):
        return arg.is_flat()
    else:
        return type(arg) in (int, str, bytes)


def is_binary(arg):
    """Return True is the argement is a binary object, which can be one of
    the following:
     - an instance of bytes
     - a tuple in the form (bytes, int)
    The second format is used to represent bit strings that do not end at a
    byte boundary. The integer number represents the number of bits in the
    last byte to be included ; its value can range between 0 and 7. The bits
    included in the last byte are the most significant ones.

    Examples:
        the 3-bit string '011' is mapped as: (b"\x60", 3)
        the 10-bit string '1111000011' is mapped as: (b"\xf0\xc0", 2)
        the 16-bit string '0000000101111111' is mapped as b"\x01\x7f"
    """
    return isinstance(arg, bytes) or (type(arg) == tuple and
                                      len(arg) == 2 and
                                      isinstance(arg[0], bytes) and
                                      type(arg[1]) == int and
                                      0 <= arg[1] <= 7)


@typecheck
def get_binary_length(arg: is_binary):
    """Return the length in bits of a binary object"""
    if isinstance(arg, bytes):
        return len(arg) * 8
    else:
        return len(arg[0]) * 8 + arg[1] - 8


def is_flatvalue_binslice(arg):
    """Return True if the argument is a tuple containing a flat Value object
    and a BinarySlice

    (format of the result of Value.decode_message())
    """

    return (type(arg) == tuple
            and len(arg) == 2
            and isinstance(arg[0], Value)
            and is_flat_value(arg[0])
            and type(arg[1]) == BinarySlice)


def is_flatvalue_binary(arg):
    """Return True if the argument is a tuple containing a flat Value object
    and a binary object (is_binary())

    (format of the result of Value.build_message())
    """
    return (type(arg) == tuple
            and len(arg) == 2
            and isinstance(arg[0], Value) and arg[0].is_flat()
            and is_binary(arg[1]))


@typecheck
def concatenate(k: iterable) -> is_binary:
    """concatenate multible binary objects (is_binary()) together

    Limitations: the current implementation accepts any binary objects as
    input, however the result of the function must end at a byte boundary
    """
    # TODO: use the 'struct' package to optimise this
    bins = []
    buff = ""
    for b in k:
        assert is_binary(b)
        #        print "*", repr(b)
        if isinstance(b, bytes) and not buff:
            # byte aligned -> nothing to do
            #            print repr(b)
            bins.append(b)
        else:
            for c in (b if isinstance(b, bytes) else b[0]):
                buff += format(c, "08b")
            if type(b) == tuple:
                buff = buff[:-8 + b[1]]
            # print "buff:", buff, repr (b)

            if len(buff) % 8 == 0:
                bins.append(bytes([eval("0b" + buff[i:i + 8]) for i in range(0, len(buff), 8)]))
                #                    print "->", repr(bins[-1])
                buff = ""

    assert not buff  # TODO: support non 8-bit aligned data ???

    return b"".join(bins)


@typecheck
def get_type(arg: either(is_data, is_type)) -> type:
    """Return the type (subclass of Value) associated to the argument.

     - if arg is a Value class     -> return arg
     - if arg is a Value instance     -> return type (arg)
     - if arg is a Template instance -> return the arg.get_type()
     - if arg is a primitive type or a primitive value ->    return the corresponding PrimitiveValue class

    The result will always be a subclass of Value

    Examples:
        >>> get_type(IntValue(45))
        <class 'core.primitive.IntValue'>

        >>> get_type(45)
        <class 'core.primitive.IntValue'>

        >>> get_type(int)
        <class 'core.primitive.IntValue'>

        >>> get_type(IntValue)
        <class 'core.primitive.IntValue'>

        >>> get_type(Range(int, 0, 15))
        <class 'core.primitive.IntValue'>

        >>> get_type(IPv6 (nh=45, len=48))
        <class 'core.lib.inet.ipv6.IPv6'>
    """

    if isinstance(arg, type):
        if issubclass(arg, Value):
            # Value class
            return arg
    else:
        if isinstance(arg, Data):
            # Data instance
            return arg.get_type()

        arg = type(arg)

    # assume that it is a primitive type
    assert arg in __known_primitive_types

    return primitive.PrimitiveValue.get_type_for_python_type(arg)


class BinarySlice:
    """Represent a slice of binary data that can begin or end at any bit
    (not necessary at a byte boundary) and that can efficiently subsliced.


    The methods of this class will raise IndexError if attempting to access
    a zone outside the current slice or if if the requested slice has its
    first bit located after the last bit.
    """

    # TODO: accept is_binary() in str_
    @typecheck
    def __init__(self, buff: bytes,
                 left: optional(int) = None,
                 right: optional(int) = None,
                 left_bits: optional(int) = None,
                 right_bits: optional(int) = None):
        """Create a new slice
        - buff        the buffer containing the slice
        - left        offset in bytes of the beginning of the slice
        - left_bits    offset in bits  of the beginning of the slice
        - right        offset in bytes of the end of the slice
        - right_bits    offset in bits  of the end of the slice

        A slice is a part of a bytes buffer. It may or may not begin
        and/or end on a byte boudary in the buffer.

        The beginning of the slice is located with the left and
        left_bits arguments and the end is located with the right and
        right_bits arguments.

        These arguments contain an offset value taken from the beginning
        of the buffer if they are positive and from the end of the
        buffer if they are negative.

        Default offsets

          If left & left_bits are ommited, the slice begins at the
          beginning of the buffer. If right & right_bits are ommited,
          the slice begins at the beginning of the buffer.

        Offset combinations

          If both left & left_bits (resp. right & right_bits) have a
          value, then these offset values will be added (note that they
          must have the same sign)

          For example the two following slices will be identical:
              BinarySlice (b"abc", left=1, left_bits=2)
            BinarySlice (b"abc", left_bits=10)
        """
        assert left is None or left_bits is None or (left * left_bits) >= 0  # same sign
        assert right is None or right_bits is None or (right * right_bits) >= 0  # same sign

        if left is None and left_bits is None:
            left_bits = 0

        self.__str = buff
        self.__left = self.__compute_offset(left, left_bits)
        self.__right = self.__compute_offset(right, right_bits)

        if self.__left > self.__right:
            raise IndexError()

    @typecheck
    def same_buffer_as(self, other_slice: this_class) -> bool:
        """Return true if both slices are based on the same buffer

        (usually when one slice is a subslice of the other one)
        """
        return self.__str == other_slice.__str

    @typecheck
    def get_right(self) -> int:
        """Return the right offset (end of the slice) in bits"""
        return self.__right

    @typecheck
    def get_left(self) -> int:
        """Return the left offset (beginning of the slice) in bits"""
        return self.__left

    # length in bytes
    @typecheck
    def __len__(self) -> int:
        """Return the length of the slice in bytes

        If slice does not contain an integer number of bytes (not a
        multiple of 8 bits), the returned result will be the floor
        value. Eg: len(BinarySlice(b"abc", right_bits=10)) == 1
        """
        return (self.__right - self.__left) // 8

    def __bool__(self) -> bool:
        "Return True if the slice is not empty"

        return self.__right != self.__left

    # length in bits
    @typecheck
    def get_bit_length(self) -> int:
        """Return the length of the slice in bits"""
        return self.__right - self.__left

    @typecheck
    def __compute_offset(self, bytes_: optional(int), bits: optional(int), relative: bool = False) -> int:
        """compute a relative offset (typically to generate a subslice)"""
        assert bytes_ is None or bits is None or (bytes_ * bits) >= 0  # same sign

        if relative:
            orig_left, orig_right = self.__left, self.__right
        else:
            orig_left, orig_right = 0, len(self.__str) * 8

        if bytes_ is None:
            if bits is None:
                result = orig_right
            elif bits >= 0:
                result = orig_left + bits
            else:
                result = orig_right + bits
        else:
            if bytes_ >= 0:
                result = orig_left + bytes_ * 8
            elif bytes_ < 0:
                result = orig_right + bytes_ * 8

            if bits:
                result += bits

        if result < orig_left or result > orig_right:
            raise IndexError()

        return result

    @typecheck
    def bit_slice(self, left: int, right: int) -> this_class:
        """Generate a subslice of this slice

        The offsets are given in bits relative to the beginning and end
        of the current slice.
        """
        left = self.__compute_offset(None, left, True)
        right = self.__compute_offset(None, right, True)

        return BinarySlice(self.__str, left_bits=left, right_bits=right)

    @typecheck
    def __getitem__(self, index: either(int, slice)) -> either(int, this_class):
        """Return the value of a byte in the slice (if index is a int)
        or a subslice (if index is a slice)

        The index is given in bytes from the beginning of the slice (if
        positive or null) or from the end of the slice (if negative).

        If a slice is requested, this function will return a BinarySlice
        objet. The offset (index.start and index.stop) are given in
        bytes relative to the beginning and the end of the current
        slice.

        NOTE: index.step is not supported (must be None)
        """

        if type(index) == int:
            return self.get_byte(index * 8)
        else:
            assert index.step is None  # increment not supported

            return BinarySlice(self.__str,
                               left_bits=self.__left if index.start is None else self.__compute_offset(index.start,
                                                                                                       None, True),
                               right_bits=self.__compute_offset(index.stop, None, True)
                               )

    @typecheck
    def get_byte(self, bit_index: int) -> int:
        """Get an individual byte in the string, starting at the offset    bit_index

        bit_index is the offset of the requested byte, given in bits
        from the beginning of the slice (if positive or zero) or from
        the endo of the slice (if negative).
        """
        #        if type (index) == slice:
        #            left  = 0 if index.start == None else self.__compute_offset (index.start, None, True)
        #            right = self.__compute_offset (index.stop , None, True)
        #            step  = index.step*8 if index.step else 8
        #            if left % 8 == 0:
        #                for i in range(0)
        #
        #            print left, right, step
        #            for i in range (*index.indices(self.__right)):
        #            raise

        left = self.__compute_offset(None, bit_index, True)

        # length remaining
        length = self.__right - left
        if not length:
            raise IndexError()

        c = self.__str[left // 8]

        if not left % 8:
            # byte-aligned

            if length < 8:
                # clear the last bits
                c = (c >> (8 - length)) << (8 - length)
        else:
            # NOT byte-aligned
            offset = left % 8

            c = (c & (0xff >> offset)) << offset

            if length > 8 - offset:
                # read a second char
                c |= (self.__str[left // 8 + 1]) >> (8 - offset)

            if length < 8:
                # clear the last bits
                c = (c >> (8 - length)) << (8 - length)
        return c

    @typecheck
    def raw(self) -> bytes:
        """Return the raw bytes string

        This function will return the content of the slice as a raw
        bytes object.

        If the size of the slice is a multiple of 8-bits, then the
        length of the resulting string will be equal to len(self)
        otherwise it will be equal to len(self)+1 and the least
        significant bits of the last byte will be padded with undefined
        values.
        """
        # TODO: optimise this
        return bytes([self.get_byte(i) for i in range(0, self.__right - self.__left, 8)])

    @typecheck
    def as_binary(self) -> is_binary:
        """Return the content of the slice as a binary object"""
        buff = self.raw()
        bit_add = self.get_bit_length() % 8
        return (buff, bit_add) if bit_add else buff

    @typecheck
    def shift_bits(self, bits: int) -> this_class:
        """Create a subslice of the current slice by removing a group of
        bits at the beginning or at the end of the slice.

        This is equivalent to:
        - self.bit_slice (bits, self.get_bit_length()) if bits>=0
        - self.bit_slice (0, bits) if bits<0
        """
        if bits >= 0:
            return BinarySlice(self.__str, left_bits=self.__compute_offset(None, bits, True), right_bits=self.__right)
        else:
            return BinarySlice(self.__str, left_bits=0, right_bits=self.__compute_offset(None, bits, True))

    def __repr__(self):
        """Return a representation of the slice evaluable in python"""
        return "BinarySlice (%s, %d, %d, %d, %d)" % (
            repr(self.__str),
            self.__left // 8,
            self.__right // 8,
            self.__left % 8,
            self.__right % 8
        )


class Data(named.NamedObject):
    """Root class for all Data object

    Data objects are used to represent test data (values and templates).

    see help(core.data) for more details
    """

    __default_name = None

    @typecheck
    def __init__(self, parent: optional(is_data) = None):
        """Constructor

        parent is the parent object of this data. Its type must be
        compatible with self.get_type() (see store_data())
        """

        named.NamedObject.__init__(self, Data.__default_name)
        self.__frozen = False
        self.__parent = None

        if parent:
            self.set_parent(parent)

    @staticmethod
    @contextmanager
    def disable_name_resolution():
        """Return a context that disables the automatic name resolution
        done by NamedObject.__init__

        All Data object have a __name__ attribute. If after its
        creation, the object is immediately store into a variable, then
        the __name__ attribute is set to the name of this variable
        (otherwise it is set to "(anon)".

        This process is convenient for tracking the name data objects,
        however it is a little time consuming and can induce significant
        delays when lots of objects are created (especially when
        encoding/decoding messages).

        This function returns a context that disables the name
        resolution. It is automatically during the execution of a
        testcase.

            >>> IntValue(12).__name__
            '(anon)'

            >>> three = IntValue(3)
            >>> three.__name__
            'three'

            >>> three_bis = three
            >>> three_bis.__name__
            'three'

            >>> with Data.disable_name_resolution():
            ...    four = IntValue(4)
            ...    print (four.__name__)
            ...
            (anon)
        """
        previous_value = Data.__default_name
        Data.__default_name = "(anon)"
        try:
            yield
        finally:
            Data.__default_name = previous_value

    @typecheck
    def set_parent(self, parent: is_data):
        """Set the parent of this data object

        Its type must be compatible with self.get_type() (see store_data())

        This function may be used only once on one object.

        NOTE: this is the only function that can alter a Data object. It
        may be removed in the future
        """
        parent = store_data(parent,
                            self.get_type())  # FIXME: the conversion might be too strict (especially with a subclass)  -> should we allow the child to be a subclass of the parent ?

        assert not self.is_frozen()
        if self.__parent is not None:
            raise exceptions.Error("This data has already one parent data")

        parent.freeze()
        self.__parent = parent

    def get_parent(self) -> optional(is_data):
        """Get the parent object this object derives from"""
        return self.__parent

    def get_type(self) -> type:
        """Return the type of Data contained in this object.

        This function returns the type of the object with the same
        meaning as the global get_type() function. The result is a
        subclass of Value.

        NOTE: the result is not necessarily equals to type(self) (this
        is true only for Value instances, Template instances store their
        type in an attribute)
        """
        raise exceptions.NotImplemented()

    @typecheck
    def datas(self) -> iterable:
        """Return an iterator on this object and its parents"""
        d = self
        while d:
            yield d
            d = d.__parent

    def freeze(self):
        """Freeze this object (make it immutable).

        NOTE: may be removed in the future
        """
        self.__frozen = True

    def is_frozen(self):
        """Return true if this object is immutable.

        NOTE: may be removed in the future
        """
        return self.__frozen

    def describe(self, desc):
        """Fill a MessageDescription object with the description of this data.

        The default implementation returns the type of the data.

        It may be reimplemented in order to give more detailed
        information (eg. source/destination addresses)

        The function return True if a description could be successfully
        extracted.
        """
        assert isinstance(desc, MessageDescription)

        desc.info = self.get_type().__name__
        return True

    @typecheck
    def match(self, value: optional(is_flat_value), mismatch_list: optional(list) = None) -> bool:
        """Return True if the argument 'value' matches the current data.

        'value' will match 'self' if all the following conditions are
        fulfilled:
         - its type is compatible ('value' is an instance of self.get_type())
         - in case 'self' derives from a parent data, 'value' must match
           this data
         - it fulfils type-specific checks implemented in self._match()

        The mismatch_list can be used to get detailed information in
        case of mismatch. If used, it must be initialised to an empty
        list which will be populated with a set of Mismatch objects.

        NOTE: This function should not be reimplemented. Specialised
        match behaviour should be implemented or reimplemented in the
        _match() member function instead.
        """

        # TODO: question: is it possible for a template to derive from multiple types ?
        #    (eg. combination of templates) -> how to handle that ???

        result = True

        if mismatch_list is not None:
            # just used to ensure that the mismatch_list is populated if and only if we have a mismatch
            initial_mismatch_list_length = len(mismatch_list)

        if value is None:
            result = False
            if mismatch_list is not None:
                mismatch_list.append(TypeMismatch(value, self))
        else:
            # FIXME: should we have automatic conversion to type(self) ?
            value = as_data(value)

            if self.__parent is None:
                # top template
                # -> first check that the data is compatible with this type

                # FIXME: should't we do this in the constructor directly ?
                if not self.get_type().is_valid_value(value):
                    result = False
                    if mismatch_list is not None:
                        mismatch_list.append(TypeMismatch(value, self))

            else:
                # child template
                # -> first check with the parent template
                if not self.__parent.match(value, mismatch_list):
                    if mismatch_list is not None:
                        # will not change the result,
                        # but this will give a more accurate mismatchlist
                        if self.get_type().is_valid_value(value):
                            self._match(value, mismatch_list)
                    result = False

            # run type-specific checks
            if result:
                result = self._match(value, mismatch_list)

        if mismatch_list is not None:
            # when _match() returns False, there must be at least one difference
            have_no_new_mismatches_entries = len(mismatch_list) == initial_mismatch_list_length

            assert have_no_new_mismatches_entries == result  # at least one mismatch entry must be created in case of mismatch

        return result

    @typecheck
    def _match(self, value: is_flat_value, mismatch_list: optional(list) = None) -> bool:
        """Specialised match method to be reimplemented in inherited
        classes

        The match() methods performs generic checks that are common to
        every Data classes:
            - check that value is an instance of self.get_type()
            - check that the value matches the parents of self (if
              any)

        This function is expected to check if 'value' matches the
        pattern described in 'self' and return True if the match is
        success.

        In case of mismatch, the function must return False and append a
        Mismatch object into the mismatch list (if present) in order to
        give details about the mismatch.
        """
        raise exceptions.NotImplemented()

    @typecheck
    def display(self, indent=0, output: with_attr("write") = sys.stdout):
        """Display the current data in a multi-line human readable way.

        Parameters:
         - indent: number of blank spaces to prepend in the result
                (for representing value encapsulation)
         - output: output stream (default: sys.stdout)
        """
        return self._display(indent, output)

    # TODO: we should keep a reference to the original template
    # FIXME: exceptions thrown by this function may be difficult to handle in practice
    def flatten(*datas) -> is_flat_value:
        """Generate a flat value from this data object and other data

        The list of data objects is split in two groups:
         - Value objects
         - Template objects

        If there is no value object, None is returned.


        In order to be flattened, the values must all have exactly the
        same type (otherwise an exception is raised).

        Then the specialised _flatten() method is called to generate the
        actual flattened value.

        The resulting value is compared with the template objects listed
        above. If there is any mismatch, then an exception is returned.


        NOTE: this function should not be reimplemented. You should
        reimplement _flatten() instead
        """

        # First we separate values and templates
        values = []
        templates = []
        for d in datas:
            d.freeze()

            if isinstance(d, Template):
                templates.append(d)
            else:
                assert isinstance(d, Value)
                values.append(d)

        # we must have at least one value
        if len(values) == 0:
            # FIXME: maybe raise an error if there are templates defined but no values
            return None

        # check that all are of compatible types
        value_class = type(values[0])

        for d in datas:
            if d.get_type() != value_class:  # FIXME: might be too strict
                raise exceptions.Error("incompatible types cannot be flattened together " + str(datas))

        # flatten the values
        result = value_class._flatten(values)

        # check that the result complies with the templates
        for t in templates:
            if not t.match(result):
                raise exceptions.Error("flattened value does not comply with one of its templates")

        return result

    def is_flat(self):
        """Return True if this data is flat

        A flat data is a Value object that has no parents and in case of
        structured objects, a value that contains only flat values.

        This function checks that this data has no parent and calls
        self._is_flat() for specialised checks.


        NOTE: this function should not be reimplemented. You should
        reimplement _is_flat() instead
        """
        return (self.__parent is None) and self._is_flat()

    @typecheck
    def __contains__(self, value: is_value) -> bool:
        '''shortcut for the match() method'''

        return self.match(value)

    @named.skip_parent_var_name
    @typecheck
    def __call__(self, *k, **kw) -> this_class:
        """Generate a derived value from this data object.

        The parameters *k, **kw are forwarded to the constructor of the
        Value class. The parent of the resulting object will be the
        current object.
        """
        v = type(self)(*k, **kw)
        v.set_parent(self)
        return v

    def __repr__(self):
        """Return a python-evaluable source representation of the data

        This function handles the inheritance aspects (setting the
        parent) and calls _repr() to generate the type-specific
        instantiation code.

        NOTE: this function should not be reimplemented. You should
        reimplement _repr() instead
        """

        if hasattr(self, "_repr"):

            if self.get_parent() is None:
                return self._repr()
            else:
                return "%s.set_parent(%s)" % (self._repr(), repr(self.get_parent()))
        else:
            # TODO: issue a warning
            return object.__repr__(self)


# TODO: maybe remove this function and use store_data instead
@typecheck
def as_data(arg: is_data, type_=None):
    """Get the arguement as a Data object

    The argument must either be an instance of Data or a python primitive value.

    If it is a primitive value, the function will generate a PrimitiveValue
    instance encapsulationg this primitive value.


    If a type is given, the function will try to convert the result into
    this type (only allowed for primitive types for the moment).
    """
    assert (not type_) or issubclass(type_, Value)

    if type_ in (None, Value):
        # no hint type, just convert the value if needed

        if isinstance(arg, Data):
            return arg
        else:
            # assume that it is a primitive type
            return primitive.PrimitiveValue.new(arg)
    else:
        # the type of the result must be the same as type_

        if isinstance(arg, type_):
            # nothing to do
            return arg
        else:
            # TODO: remove this case (it is now handled in store_data())
            try:
                # our data has a different type
                #
                # let's try to convert it

                assert issubclass(type_, primitive.PrimitiveValue)  # TODO: generalise it to all types ?
                return type_(arg)

            except Exception as e:
                raise exceptions.BadConversion(arg, type_, e)


# Return a data object
# FIXME:we check that the data is of the right type. Shall we also check that the value is allowed (eg. Subtype -> better to be done in the constructor)
# FIXME: we could remove sepecial treatment form Omit() here and use a kind of Union instead
def store_data(arg, type_=None, none_is_allowed=False, omit_is_allowed=False):
    """Prepare a data to be stored.

    store_data() is expected to be used in any place it is necessary to
    store a data object (especially in the implementation of structured
    values and templates). Actually this function is mostly implicitely used
    when creating structures Value objects. For example if one writes:
        IPv6 (hl=1, src="fe80::4242")
    the constructor of the IPv6 class will implicitely call:
        store_data (1, UInt8)    for the hl field
        store_data ("fe80::4242", IPv6Address)    for the src field
    in order to convert the input into the desired types (the type of the hl
    field is UInt8 and the type of src is IPv6Address).


    The caller may specify a target type. If the argument is an instance of
    this type, then it is used as is. Otherwise the function will try to
    build an instance of this type and will forward the argument to its
    constructor (in that case 'arg' can be anything that is accepted by the
    constructor). This is used to generate a value from a different input
    format, for example an IPv6 address is a subclass of BytesValue but is
    constructor is specialised and accepts the input value to be formatted
    as a human readable string. Thus is is possible to write:
        store_data ("ff02::1", IPv6Address)
    instead of:
        store_data (b"\xff\2\0\0\0\0\0\0\0\0\0\0\0\0\0\1", IPv6Address)

    The caller may also specify whether it accepts storing the two special
    objects:
    - None        -> undefined value
    - Omit()    -> omitted value (to represent optional fields)
    By default these two values are not allowed and the function will raise
    an exception.

    store_data() performs several important things:

    - In the case arg is equals to None it ensures that none_is_allowed is
      set and return None (otherwise it throws an exception)

    - If arg is a Template, then is ensures that it's type is compatible
      with the requested type (if given)

    - Otherwise it is assumed that the result will be a Value object
      * if no target type is given, then the function will used the input
        argument as is if it is already an instance of Value, otherwise
        it will try to convert it, assuming that it is a primitive
        python type.
      * if a target type is given, then the function uses the argument as is
        if it is an instance of this type, otherwise it will try to build
        an instance of this target type and forward the argument to its
        constructor.

    - Before returning, the Data result is frozen by calling its .freeze()
      method (Data objects are expected to be immutables, if they contain
      other objects, those must also be immutables) FIXME: this may no
      longer be needed in the future
    """
    assert type_ is None or issubclass(type_, Value)

    if arg is None:
        if none_is_allowed:
            # FIXME: it could be better to return some kind of NoneValue object here
            return None
        else:
            raise exceptions.Error("Expected a real value ('None' is not allowed)")

    if isinstance(arg, Template):
        # TODO: clarify this requirement (would never match otherwise)
        # TODO: enforce value vs. type checking in (PacketValue, ListValue, ...)._match()
        # FIXME: how to handle automatic conversions w/ issubclass (arg.get_type(), type_)
        assert type_ is None or issubclass(type_, arg.get_type()) or issubclass(arg.get_type(), type_) or (
            issubclass(arg.get_type(), Omit) and omit_is_allowed)

        data = arg

    else:
        # consider it is going to be a value
        if type_ in (None, Value):
            # no type -> just create a Value object to represent it
            data = as_data(arg)
        else:
            if omit_is_allowed and isinstance(arg, Omit):
                data = arg
            else:
                # convert to the desired type if needed
                try:
                    data = arg if isinstance(arg, type_) else type_(arg)
                except Exception as e:
                    raise exceptions.BadConversion(arg, type_, e)
    # make it immutable
    data.freeze()

    return data


@named.skip_parent_var_name
def pack(*msg_list):
    """This is a shortcut function to encapsulate datas into other datas. It
    makes a recursive call to the pack() methods of each container.

    For example:
        pack (Ethernet(), IPv6(), UDP(), "blahblah")
    is roughly equivalent to:
        Ethernet (pl=IPv6 (pl=UDP (pl="blahblah")))
    and to:
        Ethernet.pack (IPv6.pack (UDP.pack ("blahblah")))
    """
    assert len(msg_list)

    next = None
    # make an object that derives from each of the objects in the list
    # TODO: find a way to avoid duplicating anonymous objects ???
    for msg in reversed(msg_list):
        assert is_data(msg)

        if next is not None:
            next = as_data(msg).pack(next)
        else:
            next = as_data(msg)

    # set a new name for the resulting template
    candidate = named.get_parent_var_name()
    if candidate != "(anon)":  # FIXME: shouldn't this be systematic ? (we should not copy the name of the parent data)
        next.__name__ = candidate

    return next


class Value(Data):
    """Abstract base class for all object representing values.

    see help(Data)
    """

    def get_type(self):
        """Return the type (subclass of Value) associated to this data object

        For a value object, this function returns type(self)
        """
        return type(self)

    @classmethod
    def is_valid_value(cls, value: is_value):
        """Return true if the given value is compatible with the current type"""

        # FIXME: this may be too strict
        #    eg:    class U8 (metaclass = SubtypeClass (Range (int, 0, 255))):
        #            pass
        #        IntValue.is_valid_value (U8 (4))    ->  True
        #        U8.is_valid_value  (U8 (4))        ->  True
        #        U8.is_valid_value  (IntValue (4))    -> *False*
        #        U8.is_valid_value  (4)            -> *False*
        #
        #    should we implement automatic conversions ?
        #    (the same issue is also present in Data.match())
        #
        return isinstance(as_data(value), cls)

    def build_message(self):
        """Build a message from this value.

        This function is recursively called in case of structured
        values. It does not return a Message object but a tuple
        (is_flat_value, is_binary) that contains the built value and its
        binary representation of the Message object to be initialised.

        The value returned in the result may differ from self because
        the _build_message() may fill undefined fields with some default
        or some automatically computed values (eg. a checksum).

        This function only implement some sanity checks. The actual
        implementation is provided by the method _build_message().
        """
        assert self.is_flat()

        result = self._build_message()

        assert is_flatvalue_binary(result)
        assert result[0].get_type() == self.get_type()

        result[0].freeze()

        return result

    # TODO: clarify this function
    def find_type(self, t):
        raise KeyError

    def _build_message(self: is_flat_value) -> is_flatvalue_binary:
        """Implementation of the message encoder.

        This function is expected to be reimplemented.
        """
        raise exceptions.NotImplemented()

    @classmethod
    @typecheck
    def decode_message(cls, bin_slice: BinarySlice) -> is_flatvalue_binslice:
        """Decode a message of the current type from the content of a
        binary slice.

        This function is recursively called in case of structured
        values. It does not return a Message object but a tuple
        (is_flat_value, binary_slice) that contains the decoded value
        and the new slice to be used to next values. Decoding is usually
        done from left to right (starting from the beginning of the
        slice) but there is no obligation to follow this order in the
        implementation.

        At the end of the whole message decoding, the resulting slice is
        expected to be empty (otherwise Message's constructor will raise
        an exception).

        This function only implement some sanity checks. The actual
        implementation is provided by the method _decode_message().
        """

        #        assert issubclass (cls.__value_class, Value) # TODO: report this error

        value, bin_slice = cls._decode_message(bin_slice)

        # TODO: catch exceptions so as to help locating the errors
        # TODO: freeze the message after decoding ?

        # convert the result if needed
        result = as_data(value, cls), bin_slice

        # some sanity checks
        assert is_flatvalue_binslice(result)
        assert isinstance(result[0], cls)

        return result

    @classmethod
    def _decode_message(cls, bin_slice):
        """Default implementation of the message decoder.

        In the case cls is equals to the Value class, this function will
        by default decode the message as a BytesValue. Otherwise an
        exception is raised.

        This function is expected to be reimplemented.
        """

        if cls != Value:
            raise exceptions.NotImplemented()

        # by default if the field type is just 'Value' (typically for a Payload)
        # we decode as bytes
        return primitive.BytesValue._decode_message(bin_slice)


class Omit(Value):
    """Special type to be used in structured types where fields can
    optionally contain no value

    Assigning 'Omit()' to a field is different from assigning 'None'. The
    former is truly considered as a Value object whereas the latter means
    that there is no value defined.

    Thus:
     - Value.build_message() will not replace it with a default value
     - Value.match() will expect that the compared value is also equals to
       Omit() (whereas if the pattern is None, any value will be accepted)

    Omit() is encoded and decoded as an empty string.
    """

    def __new__(cls):
        """Singleton constructor"""

        # singleton
        cls.__instance = super().__new__(Omit)

        def new(cls):
            return cls.__instance

        cls.__new__ = new
        return cls.__instance

    def _build_message(self):
        return self, b""

    @classmethod
    def _decode_message(cls, bin_slice):
        return cls(), bin_slice

    def _is_flat(self):
        return True

    @classmethod
    def _flatten(cls, values):
        if all(v is cls.__instance for v in values):
            return cls.__instance
        else:
            raise exceptions.Error("Cannot flatten Omit() with other values")

    def _match(self, value, diff):
        assert self is value
        return True

    def __str__(self):
        return "(omit)"

    def __repr__(self):
        return "Omit()"


class Template(Data):
    """Abstract base class for representing templates

    see help(Data)
    """

    @typecheck
    def __init__(self, type_or_parent: either(is_type, is_data)):
        """Constructor

        type_or_parent contains either:
         - the type of this template (if this template has no parent
           data)
         - the parent data for this template (in that case, the type of
           this new template is inferred from the type of the parent)
        """

        self.__type = get_type(type_or_parent)

        if is_type(type_or_parent):
            Data.__init__(self)
        else:
            Data.__init__(self, type_or_parent)

    def get_type(self):
        """Return the type of this template

        The result is a subclass of Value (corresponding to the type
        used for initialising this template)
        """
        return self.__type

    def _is_flat(self):
        return False

    def _match(self, value, mismatch_list):
        """Specialised implementation of _match for templates

        This method is an intermediate method for implementing
        specialised matches for templates.

        In case of templates mismatch, we return only one mismatch
        object TemplateMismatch for the whole template. This function
        generates this object if needed upon the call to the method
        _template_match() if needed.
        """
        result = self._template_match(value)
        if not result and mismatch_list is not None:
            mismatch_list.append(TemplateMismatch(value, self))
        return result

    def _template_match(self, value: is_flat_value) -> bool:
        """Specialised implementation of _match to be reimplement for
        each template class

        This method shall return true if the value matches the template.
        """

        raise exceptions.NotImplemented()

    def store_data(self, data, none_is_allowed=False):
        """Shortcut to call store_data using this template's type.

        This is equivalent to calling global function:
            store_data (data, self.get_type(), none_is_allowed=...)

        By default None is not allowed.

        Omit() is never allowed (FIXME: maybe we should authorise it?)
        """
        return store_data(data, self.__type, none_is_allowed)


# NOTE: some data may appear multiple times in the tree
#    this does normally not apply to values since they are supposed to be flat
#    (but this may not be sufficent)
class Mismatch:
    """Base mismatch object to document match failures.

    If a list is given as parameter (mismatch_list) to the function
    Data.match(), it will be populated with one or more Mismatch object in
    case of failure.

    The order of the mismatches in the list does matter. In case of
    structured values, mismatches detected in its fields should be placed
    after the mismatch detected on the structured value itself (eg. length
    mismatch). This is important to ease the parsing of the mismatch list
    later.
    """

    @typecheck
    def __init__(self, value: optional(is_value), pattern: is_data):
        """Initialise the Mismatch object

         - 'pattern' it the pattern that was expected
         - 'values' is the value that failed to match the pattern
        """
        # FIXME: these attributes should not be modifiable
        self.value = value
        self.pattern = pattern

    def describe_value(self, describe_func=None) -> str:
        """Return a textual description of the input value

        It may be reimplemented

        Describe_func is an optional callable object that takes
        a value of self's type and return a textual description
        for this value.
        """
        txt = describe_func(self.value) if describe_func else None

        if txt is None:
            return str(self.value)
        else:
            return "%s (%s)" % (self.value, txt)

    def describe_expected(self, describe_func=None) -> str:
        """Return a textual description of the expected pattern

        It may be reimplemented

        Describe_func is an optional callable object that takes
        a value of self's type and return a textual description
        for this value.
        """
        txt = describe_func(self.pattern) if (describe_func and is_value(self.pattern)) else None

        if txt is None:
            return str(self.pattern)
        else:
            return "%s (%s)" % (self.pattern, txt)

    def describe_full(self, describe_func=None) -> str:
        """Return a string describing the mismatch

        The default implementation returns the name of the type of self
        and the result of describe_expected() and describe_value()

        Describe_func is an optional callable object that takes
        a value of self's type and return a textual description
        for this value.
        """
        return "%s: expected %s, got %s" % (type(self).__name__, self.describe_expected(), self.describe_value())

    def __str__(self):  # TODO: rename it as describe_brief and make describe_full the default
        """Return a string describing the mismatch

        The default implementation returns the name of the type of self
        and the result of describe_expected()
        """
        return "%s: expected %s" % (type(self).__name__, self.describe_expected())


class ValueMismatch(Mismatch):
    """Value mismatch

    The pattern is a different value.
    """
    pass


class TypeMismatch(Mismatch):
    """Type mismatch

    The pattern and the value have different types.
    """

    def describe_value(self, describe_func=None) -> str:
        return type(self.value).__name__

    def describe_expected(self, describe_func=None) -> str:
        return self.pattern.get_type().__name__


class VariantMismatch(Mismatch):
    """Variant mismatch

    The pattern and the value are derived from the same type, but have a
    different variant.
    """

    def __init__(self, v, p):
        Mismatch.__init__(self, v, p)
        assert isinstance(p, packet.PacketValue)

    def describe_value(self, describe_func=None) -> str:
        return type(self.value).__name__

    def describe_expected(self, describe_func=None) -> str:
        return self.pattern.get_variant().__name__


class LengthMismatch(Mismatch):
    """Length mismatch

    The value and the pattern have a different length
    """

    def describe_value(self, describe_func=None) -> str:
        return "%d elements" % len(self.value)

    def describe_expected(self, describe_func=None) -> str:
        return "%d elements" % len(self.pattern)


class TemplateMismatch(Mismatch):
    """Template mismatch

    The value did not match the template
    """
    pass


class DifferenceList(list):
    # (type, callable (value) -> yields (name, value))
    # TODO: design a standard interface in Data to introspect structured datas
    __handlers = {}

    def __init__(self, value):
        self.__value = value

    def callback(self, path, mismatch):
        print("%s: %s" % (".".join(path), mismatch.describe_full()))

    @classmethod
    @typecheck
    def set_handler(cls, typ: is_type, handler: callable):
        cls.__handlers[get_type(typ)] = handler

    @typecheck
    def describe(self, callback: callable = callback):

        path = []
        walkers = []
        value = self.__value

        walker = None
        path_elem = type(value).__name__
        for mismatch in self:

            while True:
                if mismatch.value is value:  # how about the case value==None ?
                    path.append(path_elem)
                    callback(path, mismatch, describe)
                    path.pop()

                    break  # next mismatch

                for typ, handler in self.__handlers.items():
                    if isinstance(value, typ):
                        walkers.append(walker)
                        walker = handler(value)
                        if path_elem is not None:
                            path.append(path_elem)

                            assert isinstance(path[-1], str)
                        break
                while True:
                    if walker is None:
                        callback(["(unknown)"], mismatch, None)
                        break

                    try:
                        path_elem, value, describe = next(walker)
                        break
                    except StopIteration:
                        path.pop()
                        walker = walkers.pop()

                if walker is None:
                    break


class Bidict:
    """An implementation of bi-directionnal dictionnary

    Bidict is a dictionnary that can be browsed by key or by value.

    The syntax for accessing its content by value is to use __getitem__ or
    __setitem__ with a slice whose stop value it the requested value.

    By default duplicate entries are not allowed. Thus if a key (or value)
    is overwritten, the previous key+value entry is deleted.

    Exemple:
        >>> bd=Bidict()
        >>> bd[1]=2
        >>> bd[1]
        2
        >>> bd[:2]
        1
        >>> bd[:2]=3
        >>> bd[3]
        2
        >>> bd[1]
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File "/home/abaire/git/ttproto/core/data.py", line 1657, in __getitem__
            return self._fwd[item]
        KeyError: 1
        >>>
    """

    @typecheck
    def __init__(self, init_entries: optional(either(dict, this_class)) = None, allow_duplicates=False):
        """Initialise the dictionnary

        Parameters:
         - init_entries: a dict or Bidict to populate this new Bidict
         - allow_duplicates: if True, duplicate entries will be allowed
           in the Bidict (default is: not allowed)
        """
        self._fwd = {}
        self._bwd = {}
        self.__allow_duplicates = allow_duplicates

        if init_entries:
            self.update(init_entries)

    def __getitem__(self, item):
        """Acces one element in the dictionnary

        Forward resolution (key -> value):

            bidict[key] returns the associated value


        Backward resolution (value -> key):

            bidict[:value] returns the associated Key


        The function raises KeyError if the value or key is not found.
        """

        if isinstance(item, slice):
            assert item.step is None

            if item.start is not None:
                # forward resolution
                assert item.stop is None

                return self._fwd[item.start]
            else:
                # backward resolution
                assert item.stop is not None

                return self._bwd[item.stop]
        else:
            # forward resolution
            return self._fwd[item]

    def __setitem__(self, item, value):
        """Add one entry in the Bidict

        Like __getitem__, this function can be used in the two
        directions:
            bidict[key] = value        (forward)
        or
            bidict[:value] = key        (backward)


        If the Bidict does not allow duplicates (see __init__), the two
        variants above will have the same result (and the previous
        entries with the same value or key will be deleted)


        When duplicates are allowed, the previous entries are not
        deleted.
        """
        if isinstance(item, slice):
            assert item.step is None

            if item.start is not None:
                # forward assignment
                assert item.stop is None

                self._set(item.start, value)
            else:
                # backward assignment
                assert item.stop is not None

                self._set(value, item.stop)
        else:
            # forward assignment
            self._set(item, value)

    def _set(self, key, value):
        if not self.__allow_duplicates:
            # remove previous associations
            if key in self._fwd:
                del self._bwd[self._fwd[key]]
            if value in self._bwd:
                del self._fwd[self._bwd[value]]

        self._fwd[key] = value
        self._bwd[value] = key

    def __iter__(self):
        """Return an iterator on the keys of the bidict"""
        return iter(self._fwd)

    def items(self):
        """Return an item iterator (key, value) using the forward dictionnary"""

        return self._fwd.items()

    def update(self, src: either(dict, this_class)):
        """Update the bidict with a set of entries"""

        for key, value in src.items():
            self._set(key, value)

    def __bool__(self):
        """Return True if the bidict is not empty"""
        return bool(self._fwd) or bool(self._bwd)

    def __repr__(self):
        return "%s({%s})" % (
            type(self).__name__,
            ", ".join("%s: %s" % (repr(k), repr(v)) for k, v in self.items())
        )


class BidictValueType(Bidict):
    """A bi-dictionnary specifically for doing value type resolution

    This bidict class is used for associating a value to a type, this is
    needed encoding and decoding messages. Typically for the TLV-like
    formats (type-length-value).

    When building a message, the "type" field is filled according to the
    type of the "value" field (eg. an IPv6 header containing an ICMPv6
    message will have its NextHeader field to be set to 58).

    When decoding a message, the content of the "type" field is used to know
    what is the expected type of the value (and thus to know which decoder
    shall be called) (eg. an IPv6 header with a NextHeder set to 58 is
    expected to contain an ICMPv6 message).


    This specialised bidict has some differences compared to Bidict:
    - the keys are Value objects   (canonicalised with as_data())
    - the values are types (subclasses of Value)  (canonicalised with
      get_type())
    - the bidict has a default value and a default type, thus if a lookup
      fails, the bidict will not raise any exception but will return the
      default value or type
    - when looking up for a type, the implementation will also look up its
      base classes if the type is not found in the bidict, it will return
      the first result it finds in type.__mro__.
    """

    @typecheck
    def __init__(self, default_value: optional(is_value), default_type: optional(is_type), *k, **kw):
        super().__init__(*k, **kw)
        self.__default_value = None if default_value is None else as_data(default_value)
        self.__default_type = None if default_type is None else get_type(default_type)

    @typecheck
    def _set(self, value: is_value, type_: is_type):
        super()._set(as_data(value), get_type(type_))

    def __getitem__(self, item):
        if not isinstance(item, slice) or item.stop is None:
            # forward resolution (Value -> Type)
            if isinstance(item, slice):
                assert item.stop is None
                assert item.step is None

                item = item.start
            try:
                return super().__getitem__(as_data(item))
            except KeyError:
                if self.__default_type is not None:
                    return self.__default_type
                else:
                    raise
        else:
            # backward resolution (Type -> Value)
            # try with all types in __mro__
            assert isinstance(item.stop, type)
            for t in get_type(item.stop).__mro__:
                try:
                    return super().__getitem__(slice(None, t, None))
                except KeyError:
                    pass
            if self.__default_value is not None:
                return self.__default_value
            else:
                raise KeyError(item.stop)

    def __repr__(self):
        return "%s(%s, %s, {%s})" % (
            type(self).__name__,
            repr(self.__default_value),
            repr(self.__default_type),
            ", ".join("%s: %s" % (repr(k), repr(v)) for k, v in self.items())
        )


class Message:
    """A class to represent a message exchanged between two entities.

    A message has two representations:
     - a value representation (which is an instance of the Value class)
     - a binary representation (which is a binary object (see is_binary())

    see help(core.data)
    """

    @typecheck
    def __init__(self, data_or_binary: either(is_data, is_binary), expected_type=None):
        """Initialise the message with either the value or the binary
        representation.

        If the input is a value, then the message is built from the
        result of Value.built_message()

        If the input is a binary object, then the expected type must be
        provided too. Then the binary is decoded using
        expected_type.decode_message() and the message is built from the
        result.    In case of decoding error, a DecodeError exception is
        raised.
        """
        if expected_type is None:
            # Build from a value
            assert is_data(data_or_binary)

            self.__value, self.__bin = as_data(data_or_binary).flatten().build_message()

        else:
            try:
                # Build from a binary message
                assert is_binary(data_or_binary)

                self.__bin = data_or_binary
                self.__value, binslice = expected_type.decode_message(BinarySlice(data_or_binary))

                self.__value.freeze()  # TODO: move this into decode_message ?

                if binslice.get_bit_length():
                    # NOTE: Put this as comment otherwise the process is too long
                    # self.__value.display()
                    raise exceptions.Error("Buffer not fully decoded (%d bits remaining)" % binslice.get_bit_length())
            except Exception as e:
                raise exceptions.DecodeError(data_or_binary, expected_type, e)

        self.__description = None

        assert is_binary(self.__bin)
        assert isinstance(self.__value, Value)
        assert self.__value.is_flat()
        assert self.__value.is_frozen()

    def get_value(self) -> Value:
        """Return the value representation of the message"""
        return self.__value

    @typecheck
    def get_binary(self) -> is_binary:
        """Return the binary representation of the message"""
        return self.__bin

    def get_description(self):
        """Return a MessageDescription object with summary information
        about the message"""

        if not self.__description:
            self.__description = MessageDescription(self)
        return self.__description

    def __str__(self):
        return "Message{%s, %s}" % (self.__value, self.__bin)

    def summary(self):
        """Return summary information about the message

        This is equivalent to str(self.get_description())
        """
        return str(self.get_description())

    def display(self, indent=0, output: with_attr("write") = sys.stdout):
        """Output a multi-line textual description of the message (value
        & binary)"""
        self.__value.display(indent, output)
        pfx = " " * indent
        print("%sEncoded as:" % pfx, file=output)
        b = self.__bin
        if isinstance(b, bytes):
            remainder = None
        else:
            remainder = b[1]
            b = b[0]
        for i in range(0, len(b), 16):
            print("%s    %s  %s" % (
                pfx,
                " ".join(format(c, "02x") for c in b[i:i + 8]),
                " ".join(format(c, "02x") for c in b[i + 8:i + 16])), file=output)
        if remainder:
            print("%s(last byte truncated at bit %d)" % (pfx, remainder), file=output)


class MessageDescription:
    """A class for describing a message

    This class is used for extracting specific informations about a message.

    The supported attributes are:
     - src        source address
     - dst        destination address
     - hw_src    hardware source address
     - hw_dst    hardware destination address
     - info        short summary about the content of the message

    At initialisation time, the MessageDescription class calls the
    describe() method on the value representation of the message.

    This method can be reimplemented in each type of message in order to
    fill specific informations.

    Attributes can be accessed using the dot notation:
        >>> md = MessageDescription(Message(IPv6(src="fe80::1234", dst="fe80::5678")/UDP(sport=1024, dport=53)/"test"))
        >>> md.src
        'fe80::1234'
        >>> md.hw_src
        ''
        >>> str(md)
        '[fe80::1234                       -> fe80::5678                      ] UDP 1024 -> domain'
    """

    # Added "src_port" and "dst_port" after e6dc5f5b0b77c6bb987374e757e14e9362191c1e
    __attrs = ("hw_src", "src", "hw_dst", "dst", "src_port", "dst_port", "info")

    @typecheck
    def __init__(self, message: Message):
        """Initialise the description from the given message"""
        message.get_value().describe(self)

    def __setattr__(self, name, value):
        """Update the value of one attribute

        NOTE: the attribute is updated if the given value is not None
        """
        assert name in self.__attrs
        if value is not None:
            super(MessageDescription, self).__setattr__(name, as_data(value))

    def __getattr__(self, name):
        """Get the content of an attribute

        If the attribute has no value set, then the function returns an
        empty string.
        """
        assert name in self.__attrs
        return ""

    def __str__(self):
        """Return a one-line summary of the message

        The format is the following:
            [src -> dst] info
        """
        src, dst = self.src, self.dst
        if (not src) and (not dst):
            src, dst = self.hw_src, self.hw_dst

        return "[%-2s -> %-2s] %s" % (src, dst, str(self.info))


from ttproto.core import primitive, packet
