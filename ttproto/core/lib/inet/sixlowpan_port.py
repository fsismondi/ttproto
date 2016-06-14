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

# TODO: maybe some import are unused

from	ttproto.core.data		import Value
from	ttproto.core.union		import *
from	ttproto.core.packet		import *
from	ttproto.core.exceptions		import Error
from	ttproto.core.typecheck		import *
from	ttproto.core.lib.inet.meta	import *
from	ttproto.core.lib.inet.basics 	import *
from	ttproto.core.lib.inet.ipv6	import *
from	ttproto.core.lib.inet.udp	import *
from	ttproto.core.lib.inet.sixlowpan	import *
from	ttproto.core.lib.inet.sixlowpan_hc import *

from	ttproto.core			import port

__all__ = [
	'SixLowpanMessagePort'
	]

class SixLowpanMessagePort (port.MessagePort):

	@typecheck
	def __init__ (self, pan_id: int, *k, compression = False):
		"""
		pan_id		PAN ID used by the port (at the 802.15.4 layer)

		compression	if True, outgoing IPv6 messages will be compressed by default
				(when .send() is called on an IPv6 message w/o any 6lowpan header)
		"""

		super().__init__(*k)

		self.__seq	= 0
		self.__pan_id	= pan_id

		self.compression = compression

		import ttproto.core.lib.ieee802154
		self.Ieee802154 = ttproto.core.lib.ieee802154.Ieee802154

	def __resolve_addr (self, ip6):
		# TODO: support manually-configured addresses

		if ip6[0] == 0xff:
			# multicast address
			if ip6 == IPv6Address ("ff02::1"):
				return b'\xff\xff'
			else:
				# mapping of multicast address (RFC4944 Section 9)
				return bytes((0x80 | (ip6[14] & 0x1f), ip6[15]))

		elif ip6[10:14] == b"\0\xff\xfe\0":
			# short address
			return bytes ((ip6[14], ip6[15]))
		else:
			# EUI-64
			return bytes((ip6[8] ^ 2,)) + ip6[9:]

	def __next_seq (self):
		with self.lock:
			result = self.__seq
			self.__seq += 1
			return result

	def send (self, value , src=None , dst=None ):
		value  = value.flatten()
		ip_hdr = None
		if isinstance (value, IPv6):
			ip_hdr = value
			value = (SixLowpanIPHC() if self.compression else SixLowpanIPv6()) / value
		elif isinstance (value, SixLowpanIPv6):
			ip_hdr = value["pl"]
		elif isinstance (value, SixLowpanIPHC):
			ip_hdr = value["pl"]
		elif isinstance (value, SixLowpanFRAG1):
			if isinstance (value["pl"] , SixLowpanIPv6):
				ip_hdr = value["pl"]["pl"]
		#elif isinstance (value, SixLowpan):
		#	if isinstance (value["pl"] , IPv6):
		#		ip_hdr = value["pl"]

		assert None not in (src, dst) or isinstance (ip_hdr, IPv6) # TODO: support other cases

		if isinstance (ip_hdr, IPv6):
			if not src:
				src = ip_hdr["src"]
			if not dst:
				dst = ip_hdr["dst"]
			if not src:
				src = IPv6Address("::")
			if not dst:
				dst = IPv6Address("::")

		super().send (
			self.Ieee802154 (
				dpid	= self.__pan_id,
				dst	= self.__resolve_addr (dst),
				src	= self.__resolve_addr (src),
				seq	= self.__next_seq(),
				pl	= value,
				ar	= 1,
			)
		)

	def match_receive (self, data: optional (is_data) = None, src=None, dst=None):
		#TODO: match the src/dst addresses
		if data is None:
			assert src is None and dst is None
			return super().match_receive()

		if issubclass (data.get_type(), IPv6):
			#FIXME: this creates an extra mismatch logevent each time the function is called
			for sixlowpan_type in (SixLowpanIPv6, SixLowpanIPHC):
				result = super().match_receive(self.Ieee802154(src=src, dst=dst)/sixlowpan_type(pl=data))
				if result:
					return result
			return None
		else:
			return super().match_receive(self.Ieee802154()/data)
