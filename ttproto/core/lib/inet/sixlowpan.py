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


from	ttproto.core.data		import *
from	ttproto.core.typecheck		import *
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.lib.inet.basics 	import *
from	ttproto.core.lib.inet.ipv6	import *
from	ttproto.core			import port

#import	ttproto.core.lib.inet.ipv6

__all__ = [
	'SixLowpan',
	'SixLowpanMESH',
	'SixLowpanIPv6',
	'SixLowpanFRAG1',
	'SixLowpanFRAGN'
]


class SixLowpan (
	metaclass = InetPacketClass,
	fields    = [
		("Dispatch",		"dp",		Bin (UInt8),	InetType (None)),
		("Payload", 		"pl", 		Value),
	]):
	"""
	defined in [RFC4944]
				1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |0 1| Dispatch  |  type-specific header
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	"""
	pass

sixlowpan_dispatch_bidict = BidictValueType (0, SixLowpan, allow_duplicates = True)
SixLowpan.get_field(0).tag._set_bidict (sixlowpan_dispatch_bidict)



class SixLowpanMESH (
	metaclass  = InetPacketClass,
	variant_of = SixLowpan,
	prune      = 0,
	fields	   = [
		("Dispatch",			"dp",	Bin (UInt2),	0b10),
		("V",				"v",	bool,		0),
		("F",				"f",	bool,	 	0),
		("HopsLeft",			"hl",	UInt4,	 	0),
		("OriginatorAddress",		"src",	Value,	 	0),
		("FinalDestinationAddress",	"dst",	Value,	 	0),
		("Payload",			"pl",	SixLowpan),
	]):
	"""
	defined in [RFC4944]:

		   Pattern    Header Type
		 +------------+-----------------------------------------------+
		 | 10  xxxxxx | MESH       - Mesh Header                      |
		 +------------+-----------------------------------------------+

			      1                   2                   3
	       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	      |1 0|V|F|HopsLft| originator address, final address
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	"""
	pass



class SixLowpanFRAG1 (
	metaclass  = InetPacketClass,
	variant_of = SixLowpan,
	prune      = 0,

	fields	   = [
		("Dispatch",			"dp",	Bin (UInt5),	0b11000),
		("DatagramSize",		"size",	UInt11,	 	0),
		("DatagramTag",			"tag",	Hex (UInt16), 	0),
		("Payload",			"pl",	Value),
	]):
	"""
	 defined in [RFC4944]:

		   Pattern    Header Type
		 +------------+-----------------------------------------------+
		 | 11  000xxx | FRAG1      - Fragmentation Header (first)     |
		 +------------+-----------------------------------------------+
				   1                   2                   3
	       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	      |1 1 0 0 0|    datagram_size    |         datagram_tag          |
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	"""
	pass



class SixLowpanFRAGN (
	metaclass  = InetPacketClass,
	variant_of = SixLowpan,
	prune      = 0,
	fields	   = [
		("Dispatch",			"dp",	Bin (UInt5),	0b11100),
		("DatagramSize",		"size",	UInt11,	 	0),
		("DatagramTag",			"tag",	Hex (UInt16), 	0),
		("DatagramOffset",		"ofs",	UInt8,	 	0),
		("Payload",			"pl",	Value),
	]):
	"""
	defined in [RFC4944]:

		   Pattern    Header Type
		 +------------+-----------------------------------------------+
		 | 11  100xxx | FRAGN      - Fragmentation Header (subsequent)|
		 +------------+-----------------------------------------------+
				   1                   2                   3
	       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	      |1 1 0 0 0|    datagram_size    |         datagram_tag          |
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	      |datagram_offset|
	      +-+-+-+-+-+-+-+-+
	"""
	pass



class SixLowpanBroadcast  (
	metaclass  = InetPacketClass,
	variant_of = SixLowpan,
	prune      = 0,
	fields	   = [
		("Dispatch",		"dp",	Bin (UInt8),	0b01010000),
		("SequenceNumber",	"seq",	UInt8,	 	0),
		("Payload",		"pl",	SixLowpan),
	]):
	"""
	 defined in [RFC4944]:

		   Pattern    Header Type
		 +------------+-----------------------------------------------+
		 | 01  010000 | LOWPAN_BC0 - LOWPAN_BC0 broadcast             |
		 +------------+-----------------------------------------------+

				 1
	       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	      |0|1|LOWPAN_BC0 |Sequence Number|
	      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	"""
	pass


class SixLowpanIPv6 ( #FIXME: not sure it is the right way to do it.
	metaclass  = InetPacketClass,
	variant_of = SixLowpan,
	prune      = 0,
	fields	   = [
		("Dispatch",			"dp",	Bin (UInt8), 0x41),
		("Payload",			"pl",	IPv6),
	]):
	"""
	defined in [RFC4944]:

		   Pattern    Header Type
		 +------------+-----------------------------------------------+
		 | 01  000001 | IPv6       - Uncompressed IPv6 Addresses      |
		 +------------+-----------------------------------------------+
	"""

	def describe (self, desc):
		return self.describe_payload (desc)


"""
Dispatch value bit pattern defined in [RFC4944]:

           Pattern    Header Type
         +------------+-----------------------------------------------+
         | 00  xxxxxx | NALP       - Not a LoWPAN frame               |
         | 01  000001 | IPv6       - Uncompressed IPv6 Addresses      |
         | 01  000010 | LOWPAN_HC1 - LOWPAN_HC1 compressed IPv6       |
         | 01  000011 | reserved   - Reserved for future use          |
         |   ...      | reserved   - Reserved for future use          |
         | 01  001111 | reserved   - Reserved for future use          |
         | 01  010000 | LOWPAN_BC0 - LOWPAN_BC0 broadcast             |
         | 01  010001 | reserved   - Reserved for future use          |
         |   ...      | reserved   - Reserved for future use          |
         | 01  111110 | reserved   - Reserved for future use          |
         | 01  111111 | ESC        - Additional Dispatch byte follows |
         | 10  xxxxxx | MESH       - Mesh Header                      |
         | 11  000xxx | FRAG1      - Fragmentation Header (first)     |
         | 11  001000 | reserved   - Reserved for future use          |
         |   ...      | reserved   - Reserved for future use          |
         | 11  011111 | reserved   - Reserved for future use          |
         | 11  100xxx | FRAGN      - Fragmentation Header (subsequent)|
         | 11  101000 | reserved   - Reserved for future use          |
         |   ...      | reserved   - Reserved for future use          |
         | 11  111111 | reserved   - Reserved for future use          |
         +------------+-----------------------------------------------+

                   Figure 2: Dispatch Value Bit Pattern
"""

sixlowpan_dispatch_bidict[0b01000001] = SixLowpanIPv6
#sixlowpan_dispatch_bidict[0b01000010] = SixLowpanHC1	# HC1 not supported
sixlowpan_dispatch_bidict[0b01010000] = SixLowpanBroadcast
#sixlowpan_dispatch_bidict[0b01111111] = SixLowpanHC1	# ESC not supported
for i in range(0b10000000, 0b11000000):
	sixlowpan_dispatch_bidict[i] = SixLowpanMESH
for i in range(0b11000000, 0b11001000):
	sixlowpan_dispatch_bidict[i] = SixLowpanFRAG1
for i in range(0b11100000, 0b11101000):
	sixlowpan_dispatch_bidict[i] = SixLowpanFRAGN


