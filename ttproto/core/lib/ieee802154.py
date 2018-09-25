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
import logging


from    ttproto.core.exceptions     import Error, DecodeError
from    ttproto.core.data       import *
from    ttproto.core.typecheck      import *
from    ttproto.core.packet     import *
from    ttproto.core.union      import *
from    ttproto.core.lib.inet.basics    import *
from    ttproto.core.lib.inet.meta  import FixedLengthBytesClass
from    ttproto.core.lib.inet.sixlowpan import SixLowpan
from    ttproto.core.lib.inet.sixlowpan_hc import SixLowpanIPHC


#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('[802.15.4 - CoDec]')

__all__ = [
    'Ieee802154ShortAddress',
    'Ieee802154Address',
    'Ieee802154',
    #'Ieee802154Ack',
]


_address_mode_descriptions = {
    0:  "not present",
    1:  "reserved",
    2:  "short",
    3:  "extended",
}


class _Reversed (PacketValue.Tag):
    def build_message (self, value, ctx):
        v, b = value.build_message()

        assert isinstance (b, bytes)  # unaligned bins not supported

        return v, bytes (reversed (b))

    def decode_message (self, type_, bin_slice, ctx):
        v, result_slice = type_.decode_message (bin_slice)

        length = result_slice.get_left() - bin_slice.get_left()

        assert result_slice.same_buffer_as (bin_slice)
        assert length % 8 == 0

        v, tmp_slice = type_.decode_message (BinarySlice (bytes (reversed (bin_slice.bit_slice (0, length)))))

        assert not tmp_slice # must be fully decoded

        return v, result_slice

class HexUInt16 (UInt16):
    def __new__ (cls, value):
        if isinstance (value, bytes):
            assert len (value) == 2
            return super().__new__ (cls, value[0]*256 + value[1])
        else:
            return super().__new__ (cls, value)

    def __str__ (self):
        return hex(self)

class Ieee802154ShortAddress (metaclass = FixedLengthBytesClass (2)):
    __reg = re.compile ("([0-9A-F]{2})[-:.]?([0-9A-F]{2})\\Z", re.I)

    def __new__ (cls, value = None):
        if isinstance (value, str):
            mo = re.match (cls.__reg, value)
            if not mo:
                raise Error("malformed IEEE 802.15.4 short address")

            value = bytes (int (v, 16) for v in mo.groups())

        return super().__new__ (cls, value)


class Ieee802154Address (
    metaclass = UnionClass,
    types     = (Ieee802154ShortAddress, Eui64Address),
):
    def __new__ (cls, value):
        if (isinstance (value, str) and len(value) > 5) or (isinstance (value, bytes) and len(value) > 2):
            return Eui64Address (value)
        else:
            if isinstance (value, int):
                log.warning("***warning: deprecated*** Ieee802154 short addresses are now coded as bytes")
                value = bytes ((value // 256, value % 256))

            return Ieee802154ShortAddress (value)



# TODO re-reimplement code/decode of ACK,DATA, BEACON and MAC control frames  with variants!

class Ieee802154 (
    metaclass = PacketClass,
    fields    = [
        ("FrameType",           "type", UInt3,      1),
        ("SecurityEnabled",     "se",   bool,       False),
        ("FramePending",        "fp",   bool,       False),
        ("AcknowlegeRequest",       "ar",   bool,       False),
        ("IntraPan",            "ip",   bool,       False),
        ("Reserved",            "rsv1", UInt3,      0),
        ("DestinationAddressingMode",   "dam",  UInt2,      0),
        ("FrameVersion",        "ver",  UInt2,      0),
        ("SourceAddressingMode",    "sam",  UInt2,      0),

        ("SequenceNumber",      "seq",  UInt8,      0),
        ("DestinationPanId",        "dpid", Optional (HexUInt16),       _Reversed(Omit())),
        ("DestinationAddress",      "dst",  Optional (Ieee802154Address),   _Reversed(Omit())),
        ("SourcePanId",         "spid", Optional (HexUInt16),       _Reversed(Omit())),
        ("SourceAddress",       "src",  Optional (Ieee802154Address),   _Reversed(Omit())),
        ("Payload",         "pl",   Value,      ""),
        ('FCS',     'fcs',  Optional ( HexUInt16), _Reversed(Omit()))
    ],

    #id = 1, # Data frame by default

    descriptions = {
        "type": {
            0:  "Beacon Frame",
            1:  "Data Frame",
            2:  "Ack Frame",
            3:  "MAC Command Frame",
        },
        "sam":  _address_mode_descriptions,
        "dam":  _address_mode_descriptions,
        "ver": {
            0:  "IEEE 802.15.4-2003",
            1:  "IEEE 802.15.4-2006",
            2:  "future use",
            3:  "future use",
        },
    }):

    def describe (self, desc):
        desc.hw_src = self["src"]
        desc.hw_dst = self["dst"]
        if not self.describe_payload (desc):
            desc.info = "IEEE 802.15.4"

        return True

    def _build_message (self):
        values = self.DataList (self._fill_default_values())

        # dst addr mode
        if self["dam"] is None and not isinstance (values["dst"], Omit):
            values["dam"] = 3 if isinstance (values["dst"], Eui64Address) else 2
        # dst pan id
        if self["dpid"] is None and values["dam"]:
            # set it to 0x0000 by default
            values["dpid"] = 0

        # src addr mode
        if self["sam"] is None and not isinstance (values["src"], Omit):
            values["sam"] = 3 if isinstance (values["src"], Eui64Address) else 2

        # intra_pan
        if not isinstance (values["sam"], Omit) and isinstance (values["spid"], Omit):
            values["ip"] = store_data (True, self.get_field ("ip").type)

        # enter a ieee_addresses context before encoding the fields so that the current
        # hw source & destination addresses are known to the upper layers
        # (needed by 6lowpan-hc)
        with SixLowpanIPHC.encapsulating_iid_context (values["src"], values["dst"]):
            values, bins = zip(*(f.tag.build_message(v, None) for f,v in zip (self.fields(), values)))

        # pack the frame control field
        seq_id = self.get_field_id ("seq")
        b = concatenate (reversed (bins[:seq_id]))
        # reverse the bytes order
        fc = bytes ((b[1], b[0]))

        return type(self) (*values), concatenate ((fc,) + bins[seq_id:])

    @classmethod
    def _decode_message (cls, bin_slice):
        #log.debug('[header] Starting to decode 802.15.4 header')
        seq_id = cls.get_field_id ("seq")

        def reversed_slice (sl):
            assert sl.get_bit_length() % 8 == 0
            return BinarySlice(bytes(reversed(sl.raw())))

        def decode_field (i, sl, t = None):
            f = cls.get_field (i)
            v, sl = f.tag.decode_message (t if t else f.type, sl, None)
            values.append (v)
            #log.debug('[header] [field] : ' + str(f)  + " || value : " +str(v))
            return sl


        def decode_FCS(bin_slice):
            bin_slice = decode_field ('fcs', bin_slice, HexUInt16)
            #log.debug(len(bin_slice))
            #log.debug(str(bin_slice))
            #log.debug(str(cls.get_field))
            return bin_slice

        # decode the Frame Control Field
        fc_slice = reversed_slice (bin_slice[:2])

        values = []
        for i in range(seq_id-1,-1,-1):
            fc_slice = decode_field (i, fc_slice)
            #log.debug('Decoding FC: ' + str(values))
        values = cls.List (reversed (values))

        #log.debug('Decoded FC: '+ str(values))

        assert not fc_slice

        bin_slice = bin_slice[2:]

        # sequence number
        bin_slice = decode_field (seq_id, bin_slice)
        #log.info('[header] [field] Decoded seq_id: ' + str(values["seq"]))

        if values["type"]==2:
            #log.info("[header] [field] The 802.15.4 message is an ACK")
            # let's make an educated guess and assume there's FCS if left bin_slice == 2
            if len(bin_slice) == 2:
                bin_slice = decode_FCS(bin_slice)
            assert len(bin_slice)==0
            return cls(*values), bin_slice

        # addresses
        sam = values ["sam"]
        dam = values ["dam"]
        intra = values ["ip"]

        am_type = (Omit, Omit, Ieee802154ShortAddress, Eui64Address)
        am_length = (0, 0, 2, 8)

        # dst pan-id
        bin_slice = decode_field ("dpid", bin_slice, None if dam else Omit)
        # dst address
        bin_slice = decode_field ("dst", bin_slice, am_type[dam])

        # src pan-id
        bin_slice = decode_field ("spid", bin_slice, Omit if (intra or not sam) else None)

        # src address
        #log.debug(str(am_type[sam]))
        bin_slice = decode_field ("src", bin_slice, am_type[sam])

        #log.debug('[header] finished processing header. Passing to Payload')

        # enter a ieee_addresses context before decoding the payload so that the current
        # hw source & destination addresses are known to the upper layers
        # (needed by 6lowpan-hc)
        with SixLowpanIPHC.encapsulating_iid_context (values["src"], values["dst"]):
            #log.debug('Starting to decode 802.15.4 payload as 6lowpan')
            # Payload
            #bin_slice = decode_field ("pl", bin_slice, SixLowpan)
            #TODO: reimplement the fall-back in a smart way (which is passive-friendly)

            try:
                bin_slice = decode_field ("pl", bin_slice, SixLowpan)
            except IndexError as e:
                # TODO: report this in a smarter way
                log.warning("Warning: unable to decode IEEE 802.15.4 payload as SixLowpan, ma "
                            "entering fallback mechanism")
                bin_slice = decode_field ("pl", bin_slice[:-2],SixLowpan)

        # let's make an educated guess and assume there's FCS if left bin_slice == 2
        if len(bin_slice) == 2:
            bin_slice = decode_FCS(bin_slice)

        return cls (*values), bin_slice

# class Ieee802154Ack (
#     metaclass = PacketClass,
#     variant_of = Ieee802154,
#     prune = 2, # I want to just keep FrameType, I'll add again seq and FCS as not consecutives fileds in parent class
#     fields = [
#          ("SequenceNumber", "seq", UInt8, 0),
#         ('FCS', 'fcs', Optional(HexUInt16), _Reversed(Omit()))
#     ]):
#     pass


import  ttproto.core.lib.ethernet
ttproto.core.lib.ethernet.ethernet_type_bidict[0x809a] = Ieee802154
