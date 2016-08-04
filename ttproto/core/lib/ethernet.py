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

import re

from	ttproto.core.exceptions		import Error
from	ttproto.core.data		import Value, BidictValueType
from	ttproto.core.typecheck		import *
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.lib.inet.basics	import *
from	ttproto.core.lib.ports		import socat

__all__ = [
	'EthernetAddress',
	'Ethernet',
	'EthernetPortTap',
]


class EthernetAddress (metaclass = FixedLengthBytesClass (6)):
	__reg = re.compile ("^([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})[-:.]?([0-9A-F]{2})\\Z", re.I)

	def __new__ (cls, value = None):
		if isinstance (value, str):
			mo = re.match (cls.__reg, value)
			if not mo:
				raise Error("malformed Ethernet address")

			value = bytes ([int (v, 16) for v in mo.groups()])

		return super().__new__ (cls, value)

	def __str__ (self):
		return ":".join ([format (c, "02x") for c in self])

ethernet_type_bidict = BidictValueType (0, bytes)

class Ethernet (
	metaclass = InetPacketClass,
	fields    = [
		("DestinationAddress",	"dst",	EthernetAddress,	"00:00:00:00:00:00"),
		("SourceAddress",	"src",	EthernetAddress,	"00:00:00:00:00:00"),
		("Type",		"type",	Hex (UInt16),		InetType (ethernet_type_bidict, "Payload")),
		("Payload",		"pl",	Value),
		("Trailer",		"trl",	bytes,			b""), #TODO: fill it in build_message if necessary
	],
	descriptions = {
		"Type": {
			0x0800: "IP",
			0x0806: "ARP",
			0x8100: "VLAN-tagged frame",
			0x86DD: "IPv6",
			0x880B: "PPP",
			0x8847: "MPLS",
			0x8848: "MPLS with upstream-assigned label",
			0x8863: "PPPoE Discovery Stage",
			0x8864: "PPPoE Session Stage",
			0x9000: "Loopback",
		}
	}):

	def describe (self, desc):
		desc.hw_src = self["src"]
		desc.hw_dst = self["dst"]

		# Added by 

		if not self.describe_payload (desc):
			#TODO: integrate the map into the InetFormat

			t = self.get_description ("type")
			desc.info = t if t else "Ethernet Type %04x" % self["type"]
		return True


@typecheck
def EthernetPortTap (name: optional(str) = None):
	assert not name or re.match ("[A-Za-z0-9]+$", name)

	name_add = (",tun-name=" + name) if name else ""

	#FIXME: it is mandatory to provide an IP address, what happens if it is already used ??)
	return socat.SocatMessagePort ("TUN:10.42.42.42/31,up,iff-no-pi,tun-type=tap" + name_add , Ethernet)

