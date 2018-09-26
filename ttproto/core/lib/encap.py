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

from ttproto.core.exceptions import Error
from ttproto.core.data import Value, BidictValueType
from ttproto.core.typecheck import *
from ttproto.core.lib.inet.meta import *
from ttproto.core.lib.inet.basics import *
from ttproto.core.lib.ports import socat
from ttproto.core.lib.ethernet import ethernet_type_bidict

__all__ = [
    'LinuxCookedCapture',
    'NullLoopback',
]


class LinuxCookedCapture(
        metaclass=InetPacketClass,
        fields=[
            ("PacketType", "pty", UInt16),
            ("AddressType", "aty", UInt16),
            ("AddressLength", "aln", UInt16),
            ("Address", "adr", Bytes8),
            ("Protocol", "pro", UInt16, InetType(ethernet_type_bidict, "Payload")),
            # FIXME: values below 1537 are treated differently (see wireshark dissector packet-sll.c)
            ("Payload", "pl", Value),
        ],
        descriptions={
            "PacketType": {
                0: "unicast to us",
                1: "broadcast",
                2: "multicast",
                3: "unicast to another host",
                4: "sent by us",
            }
        }):
    def describe(self, desc):
        return self.describe_payload(desc)


# Null Loopback cooked L2 generated in BSD systems

# check packet-null.c in wireshark for more info

# BSD AF_ values (family type values):
# BSD_AF_INET		2
# BSD_AF_ISO		7
# BSD_AF_APPLETALK	16
# BSD_AF_IPX		23
# BSD_AF_INET6_BSD	24	/* NetBSD, OpenBSD, BSD/OS */
# BSD_AF_INET6_FREEBSD	28	/* FreeBSD, DragonFly BSD */
# BSD_AF_INET6_DARWIN	30	/* OS X, iOS, anything else Darwin-based */

encap_type_bidict = BidictValueType(0, UInt32)


class NullLoopback(
        metaclass=InetPacketClass,
        fields=[
            ("AddressFamily", "AF", UInt8, InetType(encap_type_bidict, "Payload")),
            ("ProtocolFamily", "PF", UInt24),
            ("Payload", "pl", Value),
        ],
        descriptions={
            "AddressFamily": {
                2: "BSD INET",
                7: "BSD ISO",
                16: "BSD APPLETALK",
                23: "BSD IPX",
                24: "BSD INET6 BSD",
                28: "BSD INET6 FREEBSD",
                30: "BSD INET6 DARWIN"
            }

        }):
    def describe(self, desc):
        return self.describe_payload(desc)
