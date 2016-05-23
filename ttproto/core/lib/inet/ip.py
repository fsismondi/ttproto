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
from	ttproto.core.data		import BidictValueType

# default NH will be 59 (IPv6-NoNxt)
ip_next_header_bidict = BidictValueType (59, bytes)

# source:	http://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
ip_next_header_descriptions = {
    0:	"IPv6 Hop-by-Hop Option",
    1:	"Internet Control Message",
    2:	"Internet Group Management",
    3:	"Gateway-to-Gateway",
    4:	"IPv4 encapsulation",
    5:	"Stream",
    6:	"Transmission Control",
    7:	"CBT",
    8:	"Exterior Gateway Protocol",
    9:	"any private interior gateway (used by Cisco for their IGRP)",
    10:	"BBN RCC Monitoring",
    11:	"Network Voice Protocol",
    12:	"PUP",
    13:	"ARGUS",
    14:	"EMCON",
    15:	"Cross Net Debugger",
    16:	"Chaos",
    17:	"User Datagram",
    18:	"Multiplexing",
    19:	"DCN Measurement Subsystems",
    20:	"Host Monitoring",
    21:	"Packet Radio Measurement",
    22:	"XEROX NS IDP",
    23:	"Trunk-1",
    24:	"Trunk-2",
    25:	"Leaf-1",
    26:	"Leaf-2",
    27:	"Reliable Data Protocol",
    28:	"Internet Reliable Transaction",
    29:	"ISO Transport Protocol Class 4",
    30:	"Bulk Data Transfer Protocol",
    31:	"MFE Network Services Protocol",
    32:	"MERIT Internodal Protocol",
    33:	"Datagram Congestion Control Protocol",
    34:	"Third Party Connect Protocol",
    35:	"Inter-Domain Policy Routing Protocol",
    36:	"XTP",
    37:	"Datagram Delivery Protocol",
    38:	"IDPR Control Message Transport Proto",
    39:	"TP++ Transport Protocol",
    40:	"IL Transport Protocol",
    41:	"IPv6 encapsulation",
    42:	"Source Demand Routing Protocol",
    43:	"Routing Header for IPv6",
    44:	"Fragment Header for IPv6",
    45:	"Inter-Domain Routing Protocol",
    46:	"Reservation Protocol",
    47:	"General Routing Encapsulation",
    48:	"Dynamic Source Routing Protocol",
    49:	"BNA",
    50:	"Encap Security Payload",
    51:	"Authentication Header",
    52:	"Integrated Net Layer Security  TUBA",
    53:	"IP with Encryption",
    54:	"NBMA Address Resolution Protocol",
    55:	"IP Mobility",
    56:	"Transport Layer Security Protocol using Kryptonet key management",
    57:	"SKIP",
    58:	"ICMP for IPv6",
    59:	"No Next Header for IPv6",
    60:	"Destination Options for IPv6",
    61:	"any host internal protocol",
    62:	"CFTP",
    63:	"any local network",
    64:	"SATNET and Backroom EXPAK",
    65:	"Kryptolan",
    66:	"MIT Remote Virtual Disk Protocol",
    67:	"Internet Pluribus Packet Core",
    68:	"any distributed file system",
    69:	"SATNET Monitoring",
    70:	"VISA Protocol",
    71:	"Internet Packet Core Utility",
    72:	"Computer Protocol Network Executive",
    73:	"Computer Protocol Heart Beat",
    74:	"Wang Span Network",
    75:	"Packet Video Protocol",
    76:	"Backroom SATNET Monitoring",
    77:	"SUN ND PROTOCOL-Temporary",
    78:	"WIDEBAND Monitoring",
    79:	"WIDEBAND EXPAK",
    80:	"ISO Internet Protocol",
    81:	"VMTP",
    82:	"SECURE-VMTP",
    83:	"VINES",
    84:	"TTP",
    84:	"Protocol Internet Protocol Traffic Manager",
    85:	"NSFNET-IGP",
    86:	"Dissimilar Gateway Protocol",
    87:	"TCF",
    88:	"EIGRP",
    89:	"OSPFIGP",
    90:	"Sprite RPC Protocol",
    91:	"Locus Address Resolution Protocol",
    92:	"Multicast Transport Protocol",
    93:	"AX.25 Frames",
    94:	"IP-within-IP Encapsulation Protocol",
    95:	"Mobile Internetworking Control Pro.",
    96:	"Semaphore Communications Sec. Pro.",
    97:	"Ethernet-within-IP Encapsulation",
    98:	"Encapsulation Header",
    99:	"any private encryption scheme",
    100:	"GMTP",
    101:	"Ipsilon Flow Management Protocol",
    102:	"PNNI over IP",
    103:	"Protocol Independent Multicast",
    104:	"ARIS",
    105:	"SCPS",
    106:	"QNX",
    107:	"Active Networks",
    108:	"IP Payload Compression Protocol",
    109:	"Sitara Networks Protocol",
    110:	"Compaq Peer Protocol",
    111:	"IPX in IP",
    112:	"Virtual Router Redundancy Protocol",
    113:	"PGM Reliable Transport Protocol",
    114:	"any 0-hop protocol",
    115:	"Layer Two Tunneling Protocol",
    116:	"D-II Data Exchange (DDX)",
    117:	"Interactive Agent Transfer Protocol",
    118:	"Schedule Transfer Protocol",
    119:	"SpectraLink Radio Protocol",
    120:	"UTI",
    121:	"Simple Message Protocol",
    122:	"SM",
    123:	"Performance Transparency Protocol",
    126:	"Combat Radio Transport Protocol",
    127:	"Combat Radio User Datagram",
    130:	"Secure Packet Shield",
    131:	"Private IP Encapsulation within IP",
    132:	"Stream Control Transmission Protocol",
    133:	"Fibre Channel",
    138:	"MANET Protocols",
    139:	"Host Identity Protocol",
    140:	"Shim6 Protocol",
    141:	"Wrapped Encapsulating Security Payload",
    142:	"Robust Header Compression",
    253:	"Use for experimentation and testing",
    254:	"Use for experimentation and testing",
}
