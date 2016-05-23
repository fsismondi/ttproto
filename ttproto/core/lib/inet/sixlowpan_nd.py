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


from	ttproto.core.data		import Value
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.lib.inet.basics 	import *
from	ttproto.core.lib.inet.ipv6	import *
from	ttproto.core.lib.inet.icmpv6	import *

#import	ttproto.core.lib.inet.ipv6


__all__ = [
	'SixLowpanAddressRegistrationOption',
	'SixLowpanContextOption',
	'SixLowpanAuthoritativeBorderRouterOption',
	'SixARO',
	'SixABRO',
	'SixCO',
	'SixPI',
]

class _NDLifetimeDescription:
	"""Description class for 6lowpan-nd lifetimes (in unit of 60s)"""
	def __getitem__ (self, item):
		if not isinstance (item, int):
			return None

		mins = item % 60
		item //= 60
		hours = item % 24
		item //= 24
		days = item

		return "%dd %dh %dm" % (days, hours, mins)

"""
defined in [I-D.6lowpan-nd-15]:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |   Length = 2  |    Status     |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Reserved            |     Registration Lifetime     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                            EUI-64                             +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
class SixLowpanAddressRegistrationOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Option,
	id         = 31, #FIXME (TBD)
	prune      = -1,
	fields	   = [
		("Status",			"st",	UInt8,	 	0),
		("Reserved",			"rsv",	Hex (UInt24), 	0),
		("RegistrationLifetime",	"lt",	UInt16,	 	0),
		("EUI64",			"eui",	Eui64Address, 	"00:00:00:00:00:00:00:00"),
	],
	descriptions = {
		"Status": {
			0:	"Success",
			1:	"Duplicate Address",
			2:	"Neighbor Cache Full",
		},
		"RegistrationLifetime": _NDLifetimeDescription()
	}):
	pass

"""
defined in [I-D.6lowpan-nd-15]:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Length    |Context Length | Res |C|  CID  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Reserved           |         Valid Lifetime        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   .                       Context Prefix                          .
   .                                                               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
class SixLowpanContextOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Option,
	id         = 32, #FIXME (TBD2)
	prune      = -1,

	fields	   = [
		("ContextLength", 	"clen",	UInt8,		64),
		("Reserved1", 		"rsv1",	Bin (UInt3),	0),
		("C",			"c",	bool,		0),
		("CID",			"cid",	UInt4,		0),
		("Reserved2",		"rsv2",	Hex (UInt16),	0),
		("ValidLifetime",	"lt",	UInt16,		0),
		("ContextPrefix",	"pf",	IPv6Address,	InetPaddedPrefix(64, "clen")),
	],
	descriptions = {
		"ValidLifetime": _NDLifetimeDescription()
	}):
	pass

"""
defined in [I-D.6lowpan-nd-15]:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |  Length = 3   |        Version Number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Reserved                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                          6LBR Address                         +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
class SixLowpanAuthoritativeBorderRouterOption (
	metaclass  = InetPacketClass,
	variant_of = ICMPv6Option,
	id         = 33, #FIXME (TBD3)
	prune      = -1,
	fields	   = [
		("VersionNumber",	"ver",	UInt16,		0),
		("Reserved",		"rsv",	Hex (UInt32),	0),
		("6LBRAddress",		"lbr",	IPv6Address,	"::"),
	]):
	pass

def SixLowpanPI (l=0, **kw):
	return ICMPv6PI (l=l, **kw)

#Aliases
SixARO = SixLowpanAddressRegistrationOption
SixABRO = SixLowpanAuthoritativeBorderRouterOption
SixCO = SixLowpanContextOption
SixPI = SixLowpanPI
