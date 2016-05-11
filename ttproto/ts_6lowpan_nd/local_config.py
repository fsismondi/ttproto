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

EMULATION_MODE	= True

# ipv6calc --in prefix+mac --action prefixmac2ipv6 fe80::/10 00:00:00:00:00:42 --out ipv6addr
# ipv6calc --in mac --action geneui64 00:00:00:00:00:42 --out eui64

PRFX1 = "2001:0db8:1:1::"

PRFX2 = "fdea:1ffc:f851::" # Generated with http://www.sixxs.net/tools/grh/ula/

#NUT_addr	= "::"
#NUT_lladdr	= "fe80::74d7:4148:1000:29"
#NUT_hwaddr	= "76:d7:41:48:10:00:00:29"
#NUT_eui64	= "76:d7:41:48:10:00:00:29"

#NUT_addr	= "::"
#NUT_lladdr	= "fe80::74d7:4148:1000:2F"
#NUT_hwaddr	= "76:d7:41:48:10:00:00:2F"
#NUT_eui64	= "76:d7:41:48:10:00:00:2F"

NUT_addr	= "2001:db8:1:1::102:304"
NUT_lladdr	= "fe80::102:304"
NUT_hwaddr	= "0200000001020304"
NUT_eui64	= "0200000001020304"

#LBR1_lladdr	= "fe80::200:0:0:42"
#LBR1_hwaddr	= "0000000000000042"
#LBR1_eui64	= "0000000000000042"

LBR1_addr	= "2001:db8:1:1::ff:fe00:aa76"
LBR1_lladdr	= "fe80::ff:fe00:aa76"
LBR1_hwaddr	= "aa76"
LBR1_eui64	= "0200000102030405"

LBR2_addr	= "2001:db8:1:1::ff:fe00:aa77"
LBR2_lladdr	= "fe80::ff:fe00:aa77"
LBR2_hwaddr	= "aa77"
LBR2_eui64	= "0200000102030405"

LR1_addr	= "2001:db8:1:1::ff:fe00:aa78"
LR1_lladdr	= "fe80::ff:fe00:aa78"
LR1_hwaddr	= "aa78"
LR1_eui64	= "0200000102030405"

LR2_addr	= "2001:db8:1:1::ff:fe00:aa79"
LR2_lladdr	= "fe80::ff:fe00:aa79"
LR2_hwaddr	= "aa77"
LR2_eui64	= "0200000102030405"

HOST1_addr	= "2001:db8:1:1::ff:fe00:aa80"
HOST1_lladdr	= "fe80::ff:fe00:aa80"
HOST1_hwaddr	= "aa80"
HOST1_eui64	= "0200000102030405"

HOST2_addr	= "2001:db8:1:1::ff:fe00:aa81"
HOST2_lladdr	= "fe80::ff:fe00:aa81"
HOST2_hwaddr	= "aa81"
HOST2_eui64	= "0200000102030405"

TIMER1		= 30 # time to wait when we except a packet
TIMER2		= 30 # time to wait when we don't except a packet

SLEEP1		= 1

PANID		= 0x7600
