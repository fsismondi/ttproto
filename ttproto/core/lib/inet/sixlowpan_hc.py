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

import threading
from    contextlib import contextmanager

from    ttproto.core.data import Value
from    ttproto.core.union import *
from    ttproto.core.packet import *
from    ttproto.core.exceptions import Error
from    ttproto.core.typecheck import *
from    ttproto.core.lib.inet.meta import *
from    ttproto.core.lib.inet.basics import *
from    ttproto.core.lib.inet.ipv6 import *
from    ttproto.core.lib.inet.udp import *
from    ttproto.core.lib.inet.sixlowpan import *
from    ttproto.core.lib.inet.sixlowpan import sixlowpan_dispatch_bidict

# TODO: some factorisation of the compress() & decompress() functions
# FIXME: do not compress beyond the first frame (127 bytes) in case of fragmentation

__all__ = [
    "SixLowpanIPHC",
    "SixLowpanNHC",
    "SixLowpanNHC_IPExt",
    "SixLowpanNHC_UDP",
]


class _TFPad(
    metaclass=UnionClass,
    types=(UInt2, UInt4),
):
    pass


class _CompressedAddress(
    metaclass=UnionClass,
    types=(Omit, Bytes1, Bytes2, Bytes4, Bytes6, Bytes8, IPv6Address),
):
    __length_map = {
        0: Omit,
        1: Bytes1,
        2: Bytes2,
        4: Bytes4,
        6: Bytes6,
        8: Bytes8,
        16: IPv6Address,
    }

    def __new__(cls, value):
        if isinstance(value, bytes):
            assert len(value) in cls.__length_map

            return Omit() if value == b"" else cls.__length_map[len(value)](value)
        else:
            return IPv6Address(value)


class _CompressedPort(
    metaclass=UnionClass,
    types=(UInt4, UInt8, UInt16),
):
    pass


# NextHeader -> SixLowpanNHC class
sixlowpan_nhc_compress_dict = {}

# NHC_ID -> SixLowpanNHC class
sixlowpan_nhc_decompress_dict = {}


class SixLowpanNHC(
    metaclass=InetPacketClass,
    fields=[
        ("NHC_ID", "id", UInt8, InetType(None)),
        ("Value", "val", Value),
    ]):
    """
    defined in [6lowpan-hc-15]

               +----------------+---------------------------
               | var-len NHC ID | compressed next header...
               +----------------+---------------------------

                      Figure 12: LOWPAN_NHC Encoding
    """

    @classmethod
    @typecheck
    def compress(cls, next_header: int, payload: Value) -> (is_flat_value, is_binary, int):

        assert cls == SixLowpanNHC  # compress() must be reimplemented in derived classes

        try:
            new_class = sixlowpan_nhc_compress_dict[next_header]
        except KeyError:
            # cannot compress
            return Omit(), b"", 0

        return new_class.compress(next_header, payload)

    @classmethod
    @typecheck
    def decompress(cls, bin_slice: BinarySlice) -> (is_flat_value, BinarySlice, is_binary, int):
        """returns:  (decoded header, new slice, decompressed header, next header value)"""

        assert cls == SixLowpanNHC  # decompress() must be reimplemented in derived classes

        nhc_id = bin_slice[0]
        try:
            new_class = sixlowpan_nhc_decompress_dict[nhc_id]
        except KeyError:
            # cannot decompress
            raise Error("Unable to decompress 6lowpan NHC id %d" % nhc_id)

        return new_class.decompress(bin_slice)


sixlowpan_nhc_id_bidict = BidictValueType(0, SixLowpanNHC)
SixLowpanNHC.get_field(0).tag._set_bidict(sixlowpan_nhc_id_bidict)


class SixLowpanIPHC(
    metaclass=InetPacketClass,
    variant_of=SixLowpan,
    prune=0,
    fields=[
        # Base Format
        ("Dispatch", "dp", Bin(UInt3), 0b011),
        ("TF", "tf", Bin(UInt2), 0),
        ("NH", "nh", bool, 0),
        ("HLIM", "hl", Bin(UInt2), 0b10),
        ("CID", "cid", bool, 0),
        ("SAC", "sac", bool, 0),
        ("SAM", "sam", Bin(UInt2), 0),
        ("M", "m", bool, 0),
        ("DAC", "dac", bool, 0),
        ("DAM", "dam", Bin(UInt2), 0),

        # CID Extension
        ("SCI", "sci", Optional(UInt4), Omit()),
        ("DCI", "dci", Optional(UInt4), Omit()),

        # TF fields
        ("InlineECN", "iecn", Optional(Bin(UInt2)), Omit()),
        ("InlineDSCP", "idscp", Optional(Hex(UInt6)), Omit()),
        ("InlineTFPad", "ipad", Optional(_TFPad), Omit()),
        ("InlineFL", "ifl", Optional(Hex(UInt20)), Omit()),

        # NH field
        ("InlineNH", "inh", Optional(UInt8), Omit()),

        # HLIM field
        ("InlineHLIM", "ihl", Optional(UInt8), Omit()),

        # Source & Destination
        ("InlineSourceAddress", "isrc", _CompressedAddress, Omit()),
        ("InlineDestinationAddress", "idst", _CompressedAddress, Omit()),

        # Next header
        ("CompressedNextHeader", "nhc", Optional(SixLowpanNHC), Omit()),

        # TODO: add a field to contain the compressed payload ? (to allow forcing an arbitrary value)
        ("Payload", "pl", Optional(Value), Omit()),
    ],
    descriptions={
        "TF": {
            0b00: "ECN + DSCP + 4-bit Pad + Flow Label",
            0b01: "ECN + 2-bit Pad + Flow Label",
            0b10: "ECN + DSCP",
            0b11: "Elided",
        },
        "NH": {
            False: "Inline",
            True: "Compressed",
        },
        "HLIM": {
            0b00: "Hop Limit Inline",
            0b01: "Compressed hop limit = 1",
            0b10: "Compressed hop limit = 64",
            0b11: "Compressed hop limit = 255",
        },
        "CID": {
            False: "No additional context",
            True: "Context extension present",
        },
        "SAC": {
            False: "Stateless",
            True: "Stateful",
        },
        "SAM": {
            0b00: "Inline / Unspecified",
            0b01: "64 bits",
            0b10: "16 bits",
            0b11: "0 bits",
        },
        "M": {
            False: "Not Multicast",
            True: "Multicast",
        },
        "DAC": {
            False: "Stateless",
            True: "Stateful",
        },
        "DAM": {
            0b00: "Inline",
            0b01: "64 bits (multicast: 48)",
            0b10: "16 bits (multicast: 16)",
            0b11: "0 bits  (multicast: 8)",
        },
    }):
    """
    defined in [6lowpan-hc-15]:

           0                                       1
           0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
         +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         | 0 | 1 | 1 |  TF   |NH | HLIM  |CID|SAC|  SAM  | M |DAC|  DAM  |
         +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+


                Figure 2: LOWPAN_IPHC base Encoding

       TF: Traffic Class, Flow Label:  As specified in [RFC3168], the 8-bit
          IPv6 Traffic Class field is split into two fields: 2-bit Explicit
          Congestion Notification (ECN) and 6-bit Differentiated Services
          Code Point (DSCP).
          00:  ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
          01:  ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided
          10:  ECN + DSCP (1 byte), Flow Label is elided
          11:  Traffic Class and Flow Label are elided.
       NH: Next Header:
          0: Full 8 bits for Next Header are carried in-line.
          1: The Next Header field is compressed and the next header is
         encoded using LOWPAN_NHC, which is discussed in Section 4.1.

       HLIM: Hop Limit:
          00:  The Hop Limit field is carried in-line.
          01:  The Hop Limit field is compressed and the hop limit is 1.
          10:  The Hop Limit field is compressed and the hop limit is 64.
          11:  The Hop Limit field is compressed and the hop limit is 255.

       CID: Context Identifier Extension:
          0: No additional 8-bit Context Identifier Extension is used.  If
         context-based compression is specified in either SAC or DAC,
         context 0 is used.
          1: An additional 8-bit Context Identifier Extension field
         immediately follows the DAM field.

       SAC: Source Address Compression
          0: Source address compression uses stateless compression.
          1: Source address compression uses stateful, context-based
         compression.

       SAM: Source Address Mode:
          If SAC=0:
         00:  128 bits.  The full address is carried in-line.
         01:  64 bits.  The first 64-bits of the address are elided.
            The value of those bits is the link-local prefix padded with
            zeros.  The remaining 64 bits are carried in-line.
         10:  16 bits.  The first 112 bits of the address are elided.
            The value of the first 64 bits is the link-local prefix
            padded with zeros.  The following 64 bits are 0000:00ff:
            fe00:XXXX, where XXXX are the 16 bits carried in-line.
         11:  0 bits.  The address is fully elided.  The first 64 bits
            of the address are the link-local prefix padded with zeros.
            The remaining 64 bits are computed from the encapsulating
            header (e.g. 802.15.4 or IPv6 source address) as specified
            in Section 3.2.2.
          If SAC=1:
         00:  The UNSPECIFIED address, ::
         01:  64 bits.  The address is derived using context information
            and the 64 bits carried in-line.  Bits covered by context
            information are always used.  Any IID bits not covered by
            context information are taken directly from the
            corresponding bits carried in-line.  Any remaining bits are
            zero.
    """

    def describe(self, desc):
        return self.describe_payload(desc)

    def _build_message(self, ip6: optional(is_flat_value) = None) -> either((is_flat_value, is_binary, int),
                                                                            (is_flat_value, is_binary)):
        """the last value returned is the number of bytes that have been compressed in the IPv6 payload"""

        is_first_header = ip6 is None
        if is_first_header:
            # first header
            payload, payload_bin = self["pl"].build_message()
            ip6 = payload
        else:
            # subsequent header (will not include "payload") into the result
            assert self["Payload"] is None  # would be ignored anyway
            payload, payload_bin = Omit(), b""

        assert type(ip6) in (IPv6, Omit)  # TODO: support other types (would need to decode the binary)

        skip = 40

        values = self.DataList(self._fill_default_values())

        # we perform the compression only if there is an IPv6 header given
        # (otherwise we will just use the default values)
        if isinstance(ip6, IPv6):
            hwsrc, hwdst = self.get_current_iid_context()

            #######################################################
            # Traffic Class and Flow Label
            tc = ip6["tc"]
            ecn = (tc & 0b11000000) >> 6
            dscp = tc & 0b00111111
            tf = self["tf"]
            if tf is None:
                if ip6["fl"]:
                    if dscp:
                        # all are present
                        tf = 0
                    else:
                        # DSCP elided
                        tf = 1
                elif tc:
                    # Flow Label elided
                    tf = 2
                else:
                    # all are elided
                    tf = 3
                values["tf"] = tf
            if self["iecn"] is None:
                values["iecn"] = ecn if tf < 3 else Omit()
            if self["idscp"] is None:
                values["idscp"] = dscp if tf % 2 == 0 else Omit()
            if self["ipad"] is None:
                values["ipad"] = Omit() if tf >= 2 else UInt4(0) if tf == 0 else UInt2(0)
            if self["ifl"] is None:
                values["ifl"] = ip6["fl"] if tf < 2 else Omit()

            #######################################################
            # Hop Limit
            hl = ip6["hl"]
            # pre-compute a candidate value for hlim
            if self["hl"] is None:
                if hl == 1:
                    hlim = 0b01
                elif hl == 64:
                    hlim = 0b10  # FIXME: possible issue if the packet is forwarded
                elif hl == 255:
                    hlim = 0b11  # FIXME: idem, except if dsl is in fe80::/64
                else:
                    hlim = 0b00
            else:
                hlim = self["hl"]

            if self["hl"] is None:
                values["hl"] = hlim
            if self["ihl"] is None:
                values["ihl"] = Omit() if hlim else hl

            #######################################################
            # Unicast addresses compression
            def compress_unicast(ipv6_addr, hw, am_index, ac_index, addr_index):
                """returns (addr_mode, addr_comp, context_info)"""

                ci = None
                if ipv6_addr == IPV6_UNSPECIFIED_ADDRESS and am_index == "sam":  # not applicable to the dst addr
                    # special case: unspecified addr
                    ac = 1
                    am = 0
                else:
                    # interface id compression
                    if ipv6_addr[8:] == hw:
                        # full compression (Eui64 address)
                        am = 3
                    elif ipv6_addr[8:14] == b"\0\0\0\xff\xfe\0":
                        # 16-bit address pattern
                        if ipv6_addr[14:] == hw:
                            # full compression (short address)
                            am = 3
                        else:
                            # 16 bits compression
                            am = 2
                    else:
                        # no iid compression
                        am = 1

                    # prefix compression
                    if ipv6_addr[:8] == b"\xfe\x80\0\0\0\0\0\0":
                        # link-local
                        ac = 0
                    else:
                        ci = self.find_context(ipv6_addr)
                        if ci is not None and ipv6_addr != IPV6_UNSPECIFIED_ADDRESS:
                            # stateful compression
                            ac = 1
                        else:
                            # context not found -> disable all compression
                            ac = 0
                            am = 0
                            ci = None

                if self[am_index] is not None:
                    sam = self[am_index]

                if self[ac_index] is None:
                    values[ac_index] = ac
                if self[am_index] is None:
                    values[am_index] = am
                if self[addr_index] is None:
                    pfx = b"" if ac or am else ipv6_addr[:8]
                    if am == 2:
                        # 16 bits
                        iid = ipv6_addr[-2:]
                    elif am == 3:
                        # 0 bits
                        iid = b""
                    else:
                        if am == 0 and ac == 1:
                            # unspecified address
                            iid = b""
                        else:
                            # 64 bits
                            iid = ipv6_addr[-8:]

                    values[addr_index] = pfx + iid

                return ci

            #######################################################
            # Source Address
            src = ip6["src"]
            sci = compress_unicast(src, hwsrc, "sam", "sac", "isrc")

            #######################################################
            # Destination Address
            dst = ip6["dst"]
            m = dst[0] == 0xff
            if self["m"] is None:
                values["m"] = m
            if not m:
                dci = compress_unicast(ip6["dst"], hwdst, "dam", "dac", "idst")
            else:
                # multicast address compression
                dci = None
                dac = 0
                if dst[:15] == b"\xff\2\0\0\0\0\0\0\0\0\0\0\0\0\0":
                    # 8 bits
                    dam = 3
                elif dst[2:13] == b"\0\0\0\0\0\0\0\0\0\0\0":
                    # 32 bits
                    dam = 2
                elif dst[2:11] == b"\0\0\0\0\0\0\0\0\0":
                    # 48 bits
                    dam = 1
                else:
                    # 128 bits or stateful
                    dam = 0
                    dci = self.find_context(IPv6Address(dst[4:12] + bytes(8)), dst[3])
                    if dci is not None:
                        # stateful compression
                        dac = 1

                if self["dac"] is None:
                    values["dac"] = dac
                if self["dam"] is None:
                    values["dam"] = dam
                if self["idst"] is None:
                    if dac == 0:
                        if dam == 0:
                            # 128 bits
                            iid = dst
                        elif dam == 1:
                            # 48 bits
                            iid = dst[1:2] + dst[11:16]
                        elif dam == 2:
                            # 32 bits
                            iid = dst[1:2] + dst[13:16]
                        else:
                            # 8 bits
                            iid = dst[15:16]

                        values["idst"] = iid
                    else:
                        # stateful
                        assert dam == 0  # other cases are reserved

                        values["idst"] = dst[1:3] + dst[12:]

            #######################################################
            # Context Information Extension
            cid = self["cid"]
            if cid is None:
                cid = sci is not None or dci is not None
            sci = sci if sci else 0
            dci = dci if dci else 0

            if self["cid"] is None:
                values["cid"] = cid
            if self["sci"] is None:
                values["sci"] = sci if cid else Omit()
            if self["dci"] is None:
                values["dci"] = dci if cid else Omit()

            #######################################################
            # NextHeader
            if self["nhc"] is None:
                # enter and iid context because we may use to compressed addresses
                with self.encapsulating_iid_context(src, dst):
                    nhc, nhc_bin, skip_add = SixLowpanNHC.compress(ip6["nh"], ip6["pl"])
                    skip += skip_add
            else:
                nhc, nhc_bin = self["nhc"].build_message()
                skip += nhc.calc_skip()

            nh = nhc != Omit()  # TODO: document that this value may be computed from self["nhc"] (contrary to all other fields)

            if self["nh"] is None:
                values["nh"] = nh
            if self["inh"] is None:
                values["inh"] = Omit() if nh else ip6["nh"]

            if self["nhc"] is not None:
                nhc = values["nhc"]
        else:
            # build the NHC header
            nhc, nhc_bin = values["nhc"].build_message()

        #######################################################
        # Generation of the message

        # remove the payload & nhc (because they are already built)
        values.pop()
        values.pop()

        # encode the fields
        values[:], bins = zip(*(f.tag.build_message(v, None) for f, v in zip(self.fields(), values)))

        # restore the nhc & payload
        # the first header carries the whole payload (minus the headers that have been compressed)
        # (subsequent headers won't carry any payload)
        values.append(nhc)
        values.append(payload)
        bins = bins + (nhc_bin, payload_bin[skip:],)

        # assemble the result
        v = type(self)(*values)
        b = concatenate(bins)

        return (v, b) if is_first_header else (v, b, skip)

    @classmethod
    def _decode_message(cls, bin_slice, root_header=True):

        hwsrc, hwdst = cls.get_current_iid_context()

        def decoder_func():
            nonlocal bin_slice
            v = None
            for f in cls.fields():
                t = yield v
                v, bin_slice = f.tag.decode_message(t if t else f.type, bin_slice, None)
                values.append(v)
            yield v

        values = cls.DataList()

        # prepare the decoder
        decoder = decoder_func()
        next(decoder)

        def decode():
            return next(decoder)

        def decode_if(cond):
            return decoder.send(None if cond else Omit)

        def decode_as(type):
            return decoder.send(type)

        # decode the base format
        dp = decode()
        tf = decode()
        nh = decode()
        hl = decode()
        cid = decode()
        sac = decode()
        sam = decode()
        m = decode()
        dac = decode()
        dam = decode()

        # CID extension
        sci = decode_if(cid)
        dci = decode_if(cid)

        # TF fields
        iecn = decode_if(tf != 3)
        idscp = decode_if(not (tf & 1))
        ipad = decode_as(Omit if tf & 2  else (UInt2 if tf else UInt4))
        ifl = decode_if(not (tf & 2))

        # NH field
        inh = decode_if(nh == 0)

        # HLIM field
        ihl = decode_if(hl == 0)

        # src & dst addr
        def decode_unicast(am, ac):
            if am == 0:
                return decode_as(Omit if ac else IPv6Address)
            else:
                return decode_as((None, Bytes8, Bytes2, Omit)[am])

        isrc = decode_unicast(sam, sac)
        if not m:
            idst = decode_unicast(dam, dac)
        else:
            # multicast
            if dac:
                idst = decode_as(Omit if dam else Bytes6)
            else:
                idst = decode_as((IPv6Address, Bytes6, Bytes4, Bytes1)[dam])

        # compute the addresses
        def compute_unicast(am, ac, inl, hw, ci):
            if am == 0:
                return IPV6_UNSPECIFIED_ADDRESS if ac else inl
            else:
                if ac == 0:
                    pfx = b"\xfe\x80\0\0\0\0\0\0"
                else:
                    if ci == Omit():
                        raise Error("6Lowpan decompression error: packet uses stateful compression whereas CID == 0")
                    pfx, length = cls.get_context(ci)
                    pfx = pfx[:8]

                if am == 1:
                    iid = inl
                elif am == 2:
                    iid = b"\0\0\0\xff\xfe\0" + inl
                else:
                    iid = hw

                return IPv6Address(pfx + iid)

        def compute_multicast():
            if dac:
                # Stateful
                if dam == 0:
                    pfx, length = cls.get_context(dci)
                    return IPv6Address(b"".join((b"\xff", idst[:2], bytes((length,)), pfx[:8], idst[2:])))
                else:
                    return IPV6_UNSPECIFIED_ADDRESS
            else:
                # Stateless
                if dam == 0:
                    return idst
                elif dam == 1:
                    return IPv6Address(b"".join((b"\xff", idst[:1], b"\0\0\0\0\0\0\0\0\0", idst[1:])))
                elif dam == 2:
                    return IPv6Address(b"".join((b"\xff", idst[:1], b"\0\0\0\0\0\0\0\0\0\0\0", idst[1:])))
                else:
                    return IPv6Address(b"\xff\2\0\0\0\0\0\0\0\0\0\0\0\0\0" + idst)

        # decompress the addresses
        src = compute_unicast(sam, sac, isrc, hwsrc, sci)
        dst = compute_multicast() if m else compute_unicast(dam, dac, idst, hwdst, dci)

        # next compressed header
        if not nh:
            nhc = Omit()
            nhc_bin = b""
            next_header = inh
        else:
            # here were enter a pseudo_addr context because we may need to compute an IPv6 checksum
            # and enter and iid context because we may have compressed addresses
            with InetPacketValue.ipv6_pseudo_addresses_context((src, dst)), \
                 cls.encapsulating_iid_context(src, dst):

                nhc, bin_slice, nhc_bin, next_header = SixLowpanNHC.decompress(bin_slice)
        values.append(nhc)

        def value(value, default_if_omit):
            return default_if_omit if isinstance(value, Omit) else value

        # Assemble the IPv6 header
        ipv6_bin = IPv6(
            tc=(value(iecn, 0) << 6) | value(idscp, 0),
            fl=value(ifl, 0),
            len=len(bin_slice) + len(nhc_bin),
            nh=next_header,
            hl=(ihl, 1, 64, 255)[hl],
            src=src,
            dst=dst,
            pl="",
        ).build_message()[1]

        if root_header:
            # Generate the new slice
            inner_slice = BinarySlice(concatenate((ipv6_bin, nhc_bin, bin_slice.as_binary())))

            # Decode the payload
            payload, inner_slice = IPv6.decode_message(inner_slice)
            values.append(payload)

            if inner_slice:
                raise Error("Buffer not fully decoded (%d remaining bits)" % inner_slice.get_bit_length())

            return cls(*values), bin_slice.shift_bits(bin_slice.get_bit_length())
        else:
            values.append(Omit())
            return cls(*values), bin_slice, ipv6_bin + nhc_bin

    __local = threading.local()

    @staticmethod
    @contextmanager
    def encapsulating_iid_context(src, dst):
        def conv_iid(addr):
            if isinstance(addr, IPv6Address):
                # IPv6 address
                return addr[8:]
            elif isinstance(addr, Eui64Address):
                # EUI-64 address
                return bytes((addr[0] ^ 2,)) + addr[1:]
            else:
                # 802.15.4 short address
                assert isinstance(addr, bytes)
                assert len(addr) == 2
                return b"\0\0\0\xff\xfe\0" + addr

        l = SixLowpanIPHC.__local
        backup = l.iids if hasattr(l, "iids") else (None, None)

        l.iids = conv_iid(src), conv_iid(dst)
        try:
            yield
        finally:
            l.iids = backup

    @staticmethod
    def get_current_iid_context():
        l = SixLowpanIPHC.__local
        return l.iids if hasattr(l, "iids") else (None, None)

    __contextes_lock = threading.Lock()
    __contextes_stack = []
    __contextes = tuple((IPV6_UNSPECIFIED_ADDRESS, 128) for i in range(0, 16))

    @classmethod
    @contextmanager
    def contextes(cls, *k):
        """k is a list of tuples (id, prefix, length)

            eg:	((1,  "aaaa::", 64),
                 (12,b"1234560000000000", 48))

        """

        with cls.__contextes_lock:
            # copy the current context
            contextes = list(cls.__contextes)
            # push it into the stack
            cls.__contextes_stack.append(cls.__contextes)
            # update the new context
            for id, pfx, length in k:
                assert 0 <= id <= 15
                assert 0 <= length <= 128
                contextes[id] = store_data(pfx, IPv6Address), length
            # use it as the current context
            cls.__contextes = contextes

        try:
            yield
        finally:
            with cls.__contextes_lock:
                if cls.__contextes is contextes:
                    # restore the previous from the stack
                    cls.__contextes = cls.__contextes_stack.pop()
                else:
                    # may happen if the contextes are modified by multiple threads
                    # -> remove the corresponding entry in the stack
                    cls.__contextes_stack.remove(contextes)

    @classmethod
    @typecheck
    def get_context(cls, id: int) -> (IPv6Address, id):
        assert 0 <= id <= 15
        with cls.__contextes_lock:
            return cls.__contextes[id]

    @classmethod
    @typecheck
    def find_context(cls, addr: IPv6Address, length=None) -> optional(int):
        with cls.__contextes_lock:
            if length is None:
                # address lookup
                i = 0
                for pfx, length in cls.__contextes:
                    if IPv6Prefix(pfx, length).match(addr) \
                            and IPv6Prefix(addr, length).get_address() == IPv6Prefix(addr, 64).get_address():
                        return i
                    i += 1
                return None
            else:
                # prefix lookup
                try:
                    return cls.__contextes.index((addr, length))
                except ValueError:
                    return None

    @classmethod
    def print_contextes(cls):
        print("IPHC contextes")
        for i, ctx in zip(range(0, 16), cls.__contextes):
            print("  %02d -> %s/%d" % (i, ctx[0], ctx[1]))


class _IPExtNHC(
    metaclass=UnionClass,
    types=(Omit, SixLowpanNHC, SixLowpanIPHC),
):
    pass


class SixLowpanNHC_IPExt(
    metaclass=InetPacketClass,
    variant_of=SixLowpanNHC,
    prune=0,
    fields=[
        ("NHC_ID", "id", UInt4, 0b1110),
        ("ExtensionHeaderId", "eid", UInt3, 0),
        ("NextHeader", "nh", bool, False),
        ("InlineNextHeader", "inh", Optional(UInt8), Omit()),
        ("InlineLength", "ilen", Optional(UInt8), Omit()),
        ("InlineValue", "ival", Optional(bytes), Omit()),
        ("CompressedNextHeader", "nhc", _IPExtNHC, Omit()),
    ],
    descriptions={
        "nh": {
            False: "Inline",
            True: "Compressed",
        },
        "id": {
            0: "Hop-by-Hop",
            1: "Routing",
            2: "Fragment",
            3: "Destination",
            4: "Mobility",
            7: "IPv6",
        },
    }):
    __type_bidict = Bidict({
        # TODO: add extension headers

        7: IPv6,
    })

    @classmethod
    @typecheck
    def compress(cls, next_header: int, payload: Value) -> (is_flat_value, is_binary, int):

        values = cls.DataList(cls()._fill_default_values())

        if next_header == 41:  # IPv6

            # compress the next IPv6 header recursively
            iphc, iphc_bin, skip = SixLowpanIPHC()._build_message(payload)

            values["eid"] = 7
            values[:], bins = zip(*(f.tag.build_message(v, None) for f, v in zip(cls.fields(), values)))

            values["nhc"] = iphc
            bins = bins + (iphc_bin,)

            return cls(*values), concatenate(bins), skip
        else:
            assert False  # TODO: extension headers compression

    @classmethod
    @typecheck
    def decompress(cls, bin_slice: BinarySlice):

        def decoder_func():
            nonlocal bin_slice
            v = None
            for f in cls.fields():
                t = yield v
                v, bin_slice = f.tag.decode_message(t if t else f.type, bin_slice, None)
                values.append(v)
            yield v

        values = cls.DataList()

        # prepare the decoder
        decoder = decoder_func()
        next(decoder)

        def decode():
            return next(decoder)

        def decode_if(cond):
            return decoder.send(None if cond else Omit)

        def decode_as(type):
            return decoder.send(type)

        nhc_id = decode()
        eid = decode()
        nh = decode()
        if eid == 7:
            # IPv6
            decode_as(Omit())  # inh
            decode_as(Omit())  # ilen
            decode_as(Omit())  # ival

            nhc, bin_slice, ip6_bin = SixLowpanIPHC._decode_message(bin_slice, False)
            values.append(nhc)

            return cls(*values), bin_slice, ip6_bin, 41

        else:
            assert False  # TODO implement extension headers decompression


class SixLowpanNHC_UDP(
    metaclass=InetPacketClass,
    variant_of=SixLowpanNHC,
    prune=0,
    fields=[
        ("NHC_ID", "id", UInt5, 0b11110),
        ("Checksum", "c", bool, True),
        ("Ports", "p", UInt2, 0),
        ("InlineSourcePort", "isp", _CompressedPort, UInt16(0)),
        ("InlineDestinationPort", "idp", _CompressedPort, UInt16(0)),
        ("InlineChecksum", "ic", Optional(Hex(UInt16)), Omit()),
    ],
    descriptions={
        "c": {
            False: "Inline",
            True: "Elided",
        },
        "p": {
            0b00: "Inline",
            0b01: "16 bits src/8 bits dst",
            0b10: "8 bits src/16 bits dst",
            0b11: "4 bits src/4 bits dst",
        },
    }):
    def calc_skip(self):
        return 8

    @classmethod
    @typecheck
    def compress(cls, next_header: int, udp: Value) -> (is_flat_value, is_binary, int):

        assert isinstance(udp, UDP)  # TODO: support other types (would have to decode it)

        sport = udp["sport"]
        dport = udp["dport"]

        if (sport & 0xfff0) == (dport & 0xfff0) == 0xf0b0:
            # 4 bits + 4 bits
            isp = UInt4(sport & 0xf)
            idp = UInt4(dport & 0xf)
            p = 3
        elif (sport & 0xff00) == 0xf000:
            # 8 bits + 16 bits
            isp = UInt8(sport & 0xff)
            idp = dport
            p = 2
        elif (dport & 0xff00) == 0xf000:
            # 16 bits + 8 bits
            isp = sport
            idp = UInt8(dport & 0xff)
            p = 1
        else:
            # 16 bits + 16 bits
            isp = sport
            idp = dport
            p = 0

        return cls(
            c=0,  # FIXME: how to specify that the checksum should be compressed ?
            p=p,
            ic=udp["Checksum"],
            isp=isp,
            idp=idp,
        ).build_message() + (8,)

    @classmethod
    @typecheck
    def decompress(cls, bin_slice: BinarySlice):

        def decoder_func():
            nonlocal bin_slice
            v = None
            for f in cls.fields():
                t = yield v
                v, bin_slice = f.tag.decode_message(t if t else f.type, bin_slice, None)
                values.append(v)
            yield v

        values = cls.DataList()

        # prepare the decoder
        decoder = decoder_func()
        next(decoder)

        def decode():
            return next(decoder)

        def decode_if(cond):
            return decoder.send(None if cond else Omit)

        def decode_as(type):
            return decoder.send(type)

        nhc_id = decode()
        c = decode()
        p = decode()
        isp = decode_as((UInt16, UInt16, UInt8, UInt4)[p])
        idp = decode_as((UInt16, UInt8, UInt16, UInt4)[p])
        ic = decode_if(not c)

        value = cls(*values)

        # decompress the values
        def port_value(inl):
            if isinstance(inl, UInt16):
                return inl
            elif isinstance(inl, UInt8):
                return 0xf000 | inl
            else:
                assert isinstance(inl, UInt4)
                return 0xf0b0 | inl

        sport = port_value(isp)
        dport = port_value(idp)
        length = len(bin_slice) + 8

        if ic == Omit():
            # recompute the checksum on the fly
            udp_bin = UDP(sport, dport, length, None, bin_slice.raw()).build_message()[1][:8]
        else:
            # use the inline checksum
            udp_bin = UDP(sport, dport, length, ic, b"").build_message()[1]

        return value, bin_slice, udp_bin, 17


# register the NHC compression headers
sixlowpan_nhc_compress_dict.update((
    (0, SixLowpanNHC_IPExt),  # Hop by Hop
    (43, SixLowpanNHC_IPExt),  # Routing Header
    (44, SixLowpanNHC_IPExt),  # Fragment Header
    (60, SixLowpanNHC_IPExt),  # Destination Options Header
    (135, SixLowpanNHC_IPExt),  # Mobility Header
    (41, SixLowpanNHC_IPExt),  # IPv6
    (17, SixLowpanNHC_UDP),  # UDP
))
for i in range(0b11100000, 0b11110000):
    sixlowpan_nhc_decompress_dict[i] = SixLowpanNHC_IPExt
for i in range(0b11110000, 0b11111000):
    sixlowpan_nhc_decompress_dict[i] = SixLowpanNHC_UDP

sixlowpan_nhc_decompress_dict.update((
    (0, SixLowpanNHC_IPExt),  # Hop by Hop
    (43, SixLowpanNHC_IPExt),  # Routing Header
    (44, SixLowpanNHC_IPExt),  # Fragment Header
    (60, SixLowpanNHC_IPExt),  # Destination Options Header
    (135, SixLowpanNHC_IPExt),  # Mobility Header
    (41, SixLowpanNHC_IPExt),  # IPv6
    (17, SixLowpanNHC_UDP),  # UDP
))

# register the 6lowpan dispatch values "011xxxxx"
for i in range(0b01100000, 0b10000000):
    sixlowpan_dispatch_bidict[i] = SixLowpanIPHC
