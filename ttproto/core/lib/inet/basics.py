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

import re, socket

from	ttproto.core.data		import *
from	ttproto.core.typecheck		import *
from	ttproto.core.exceptions		import Error
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.primitive		import BytesValue

__all__ = [
	'UInt2',
	'UInt3',
	'UInt4',
	'UInt5',
	'UInt6',
	'UInt8',
	'UInt11',
	'UInt13',
	'UInt16',
	'UInt20',
	'UInt24',
	'UInt32',
	'UInt64',
	'UInt80',
	'Bytes1',
	'Bytes2',
	'Bytes4',
	'Bytes6',
	'Bytes8',
	'Bytes10',
	'IPv4Address',
	'IPv6Address',
	'IPv6Prefix',
	'ICMPv6LLAddress',
	'Eui64Address',
]

class UInt2  (metaclass = UnsignedBigEndianIntClass ( 2)):	pass
class UInt3  (metaclass = UnsignedBigEndianIntClass ( 3)):	pass
class UInt4  (metaclass = UnsignedBigEndianIntClass ( 4)):	pass
class UInt5  (metaclass = UnsignedBigEndianIntClass ( 5)):	pass
class UInt6  (metaclass = UnsignedBigEndianIntClass ( 6)):	pass
class UInt8  (metaclass = UnsignedBigEndianIntClass ( 8)):	pass
class UInt11 (metaclass = UnsignedBigEndianIntClass (11)):	pass
class UInt13 (metaclass = UnsignedBigEndianIntClass (13)):	pass
class UInt16 (metaclass = UnsignedBigEndianIntClass (16)):	pass
class UInt20 (metaclass = UnsignedBigEndianIntClass (20)):	pass
class UInt24 (metaclass = UnsignedBigEndianIntClass (24)):	pass
class UInt32 (metaclass = UnsignedBigEndianIntClass (32)):	pass
class UInt64 (metaclass = UnsignedBigEndianIntClass (64)):	pass
class UInt80 (metaclass = UnsignedBigEndianIntClass (80)):	pass

class Bytes1 (metaclass = FixedLengthBytesClass (1)):	pass
class Bytes2 (metaclass = FixedLengthBytesClass (2)):	pass
class Bytes4 (metaclass = FixedLengthBytesClass (4)):	pass
class Bytes6 (metaclass = FixedLengthBytesClass (6)):	pass
class Bytes8 (metaclass = FixedLengthBytesClass (8)):	pass
class Bytes10 (metaclass = FixedLengthBytesClass (10)):	pass

class IPv4Address (metaclass = FixedLengthBytesClass (4)):

	def __new__ (cls, value = None):
		# TODO: normalise the exceptions

		if isinstance (value, str):
			# convert from the textual representation
			value = socket.inet_pton (socket.AF_INET, value)

		return super().__new__(cls, value)

	def __str__ (self):
		# TODO: normalise the exceptions
		return socket.inet_ntop (socket.AF_INET, self)

	def _repr (self):
		return repr (self.__str__())

class IPv6Address (metaclass = FixedLengthBytesClass (16)):

	def __new__ (cls, value = None):
		# TODO: normalise the exceptions

		if isinstance (value, str):
			# convert from the textual representation
			value = socket.inet_pton (socket.AF_INET6, value)

		return super().__new__(cls, value)

	def __str__ (self):
		# TODO: normalise the exceptions
		return socket.inet_ntop (socket.AF_INET6, self)

	def _repr (self):
		return repr (self.__str__())



class ICMPv6LLAddress (BytesValue):

	__re_sep = re.compile ("[-.:]")

	def __new__ (cls, value = b""):
		# TODO: normalise the exceptions
		if isinstance (value, str):
			elems = re.split (cls.__re_sep, value)
#			print (value, elems)
			bins = []
			for e in elems:
				if len(e) % 2:
					e = "0" + e
				for i in range (0, len(e), 2):
					# convert from hex

					bins.append (int (e[i:i+2], 16))
			value = bytes (bins)

		if not (isinstance (value, bytes)):
			value = bytes (value)

		# add padding bytes
		return super().__new__ (cls, value + bytes ((6 - len(value)) % 8))

	def __str__ (self):
		return ":".join ("%02x" % c for c in self)

class Eui64Address (metaclass = FixedLengthBytesClass (8)):
	__reg = re.compile ("^([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})\\Z", re.I)

	def __new__ (cls, value = None):
		if isinstance (value, str):
			mo = re.match (cls.__reg, value)
			if not mo:
				raise Error("malformed EUI-64 address")

			value = bytes ([int (v, 16) for v in mo.groups()])

		return super().__new__ (cls, value)


class IPv6Prefix (Template):
	@typecheck
	def __init__ (self, addr, length: optional(int) = None):
		Template.__init__ (self, IPv6Address)

		if length is None:
			if isinstance (addr, str) and "/" in addr:
				# address in the format "<addr>/<prefix>"
				addr, length = addr.split("/")
				length = int (length)
			else:
				# default to 64 bits
				length = 64

		assert 0 <= length <= 128
		addr = self.store_data (addr)
		prune_id = length // 8
		bitadd = length & 7
		if bitadd:
			# complex case (mask does not end at a byte boundary)
			shift = 8 - bitadd
			self.__addr = IPv6Address (addr[:prune_id] + bytes((addr[prune_id] >> shift << shift,)) + bytes(15 - prune_id))
		else:
			# simple case (mask ending at a byte boundary)
			self.__addr = IPv6Address (addr[:prune_id] + bytes(16-prune_id))

		self.__len = length

	def get_address(self):
		return self.__addr

	def get_length(self):
		return self.__len

	def _match (self, addr, difference_list = None):
		if self == IPv6Prefix (addr, self.__len):
			return True
		elif difference_list is not None:
			difference_list.append (ValueMismatch (addr, self))
		return False

	@typecheck
	def __eq__ (self, other):
		return isinstance (other, IPv6Prefix) and self.__addr == other.__addr and self.__len == other.__len

	def __ne__ (self, other):
		return not self == other

	def __str__ (self):
		return "%s/%d" % (str(self.__addr), self.__len)

	def __hash__ (self):
		return hash (hash (self.__addr) + self.__len)

	def __repr__ (self):
		return "IPv6Prefix('%s/%d')" % (str(self.__addr), self.__len)


	@typecheck
	def make_address (self, hwaddr: bytes):
		assert type (hwaddr).__name__ in ("Eui64Address", "EthernetAddress", "Ieee802154ShortAddress")
		assert self.__len <= 64


		if len (hwaddr) == 6:
			# Ethernet Address
			return IPv6Address (self.__addr[:8] + bytes((hwaddr[0] ^ 2,)) + hwaddr[1:3] + b"\xff\xfe" + hwaddr[3:])
		elif len (hwaddr) == 8:
			# EUI-64 Address
			return IPv6Address (self.__addr[:8] + bytes((hwaddr[0] ^ 2,)) + hwaddr[1:])

		else:
			assert len(hwaddr) == 2

			# short IEEE 802.15.4 Address
			return IPv6Address (self.__addr[:8] + b"\0\0\0\xff\xfe\0" + hwaddr)




