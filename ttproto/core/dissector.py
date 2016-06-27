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

import itertools

from ttproto.core.data import Data, Message
from ttproto.core.packet import Value, PacketValue
from ttproto.core.list import ListValue
from ttproto.core.typecheck import *
from ttproto.core.lib.ports.pcap import PcapReader

# TODO: Cleanse this mess
import ttproto.core.lib.inet.all
from ttproto.core.lib.ethernet import *
from ttproto.core.lib.ieee802154 import *
from ttproto.core.lib.encap import *
from ttproto.core.lib.inet.ipv4 import *
from ttproto.core.lib.inet.ipv6 import *
from ttproto.core.lib.inet.udp import *
from ttproto.core.lib.inet.coap import *
from ttproto.core.lib.inet.sixlowpan import *
from ttproto.core.lib.inet.sixlowpan_hc import *
from collections import OrderedDict


__all__ = [
    'Frame',
    'Dissector'
]


class Frame:
    """
        Class to represent a frame object
    """

    @classmethod
    @typecheck
    def create_list(cls, pcap_frames: PcapReader):
        """
        The dissector tool initialisation which receives a filename

        :param pcap_frames: The frames got from pcap using the PcapReader
        :type PcapReader: str

        :return: A list of Frame objects
        :rtype: list(Frame)
        """
        return list(cls(i, f) for i, f in zip(itertools.count(1), pcap_frames))

    @typecheck
    def __init__(
        self, id: int,
        pcap_frame: (
            float,
            Message,
            optional(Exception)
        )
    ):
        """
        The init function of the Frame object

        :param id: The id of the current frame
        :param pcap_frame: The frame tuple got from reading the PcapReader
        :type id: int
        :type pcap_frame: tuple(float, Message, Exception)
        """

        # Put the incremented id of this frame
        self.id = id

        # Get the 3 values of a frame given by the PcapReader
        # ts: Its timestamp value (from the header)
        # msg: Its message read directly from bytes (can be decoded)
        # exc: Exception if one occured
        self.ts, self.msg, self.exc = pcap_frame

        # Extract its informations
        self.__extract_infos()

    def __repr__(self):
        """
        Little function to display a frame object

        :return: A string representing this frame object
        :rtype: str
        """
        return "<Frame %3d: %s>" % (self.id, self.msg.summary())

    def __extract_infos(self):
        """
        Extract informations from its private values
        """

        # The informations about the current frame
        self.src = None
        self.dst = None
        self.coap = None  # This part should be externalized

        # Get the value of the message as bytes
        v = self.msg.get_value()

        # Here just pop the values one by one in packets descriptions
        while True:
            if any((
                isinstance(v, Ethernet),
                isinstance(v, IPv6),
                isinstance(v, IPv4)
            )):
                self.src = v["src"]
                self.dst = v["dst"]
                v = v["pl"]
                continue
            elif isinstance(v, UDP):
                if not isinstance(self.src, tuple):
                    self.src = self.src, v["sport"]
                    self.dst = self.dst, v["dport"]
                v = v["pl"]
                continue
            elif isinstance(v, CoAP):
                self.coap = v
            elif isinstance(v, Ieee802154):
                self.src = v["src"]
                self.dst = v["dst"]
                v = v["pl"]
                continue
            elif any((
                isinstance(v, SixLowpan),
                isinstance(v, LinuxCookedCapture),
                isinstance(v, NullLoopback)
            )):
                try:
                    v = v["pl"]
                    continue
                except KeyError:
                    pass
            break


class Dissector:
    """
        Class for the dissector tool
    """

    @typecheck
    def __init__(self, filename: str):
        """
        The dissector tool initialisation which receives a filename

        :param filename: Filename of the pcap file to be dissected
        :type filename: str
        """

        # Get the reader of the file (this can throw an exception)
        self.__reader = PcapReader(filename)

    def __del__(self):
        del self.__reader

    @typecheck
    def summaries(
        self,
        protocol: optional(PacketValue) = None
    ) -> [(int, str)]:
        """
        The summaries function to get the summary of frames

        :param protocol:  Protocol class for filtering purposes
        :type protocol: PacketValue

        :return: Basic informations about frames like the underlying example
        :rtype: list( tuple(int, str) )

        :Example:

            [
                (13, '[127.0.0.1 -> 127.0.0.1] CoAP [CON 38515] GET /test'),
                (14, '[127.0.0.1 -> 127.0.0.1] CoAP [ACK 38515] 2.05 Content'),
                (21, '[127.0.0.1 -> 127.0.0.1] CoAP [CON 38516] PUT /test'),
                (22, '[127.0.0.1 -> 127.0.0.1] CoAP [ACK 38516] 2.04 Changed')]
            ]

        .. todo:: Filter uninteresting frames ? (to decrease the load)
        """

        # Disable the name resolution in order to improve performances
        with Data.disable_name_resolution():

            # Read the file and get an iterator on it
            frames = Frame.create_list(self.__reader)

            # Prepare the response object
            response = []

            # Content of the response, TODO make this generic for any protocol
            if protocol is CoAP:
                selected_frames = [f for f in frames if f.coap]
            else:
                selected_frames = frames

            for f in selected_frames:
                    response.append((f.id, f.msg.summary()))
            # malformed frames
            # malformed = list (filter ((lambda f: f.exc), frames))
        return response

    @typecheck
    def value_to_list(
        self,
        l: list,
        value: Value,
        extra_data: optional(str) = None,
        layer_dict: optional(dict) = None,
        is_option: optional(bool) = False
    ):

        # points to packet
        if isinstance(value, PacketValue):

            od = OrderedDict()

            if is_option:
                od['Option'] = value.get_variant().__name__
            else:
                od['_type'] = 'protocol'
                od['_protocol'] = value.get_variant().__name__

            l.append(od)

            i = 0
            for f in value.get_variant().fields():
                self.value_to_list(l, value[i], f.name, od)
                i += 1

        # TODO test this
        elif isinstance(value, ListValue):
            prot_options = []
            for i in range(0, len(value)):
                self.value_to_list(prot_options, value[i], is_option=True)
            layer_dict['Options'] = prot_options

        # it's a field
        else:
            layer_dict[extra_data] = str(value)

    @typecheck
    def dissect(
        self,
        protocol: optional(PacketValue) = None
    ) -> list:
        """
        The dissect function to dissect a pcap file into list of frames

        :param filename: filename of the pcap file to be dissected
        :param protocol:  protocol class for filtering purposes (inheriting from packet Value)
        :return: List of frames (frames as Ordered Dicts)
        """

        if protocol:
            assert issubclass(protocol, PacketValue)

        frame_list = []

        # for speeding up the process
        with Data.disable_name_resolution():

            frames = Frame.create_list(self.__reader)

            for f in frames:

                # if we are filtering and frame doesnt contain protocol
                # then skip frame
                # TODO make this generic for any type of protocol
                if protocol and not f.coap:
                    pass
                else:
                    frame = OrderedDict()
                    frame['_type'] = 'frame'
                    frame['id'] = f.id
                    frame['timestamp'] = f.ts
                    frame['error'] = f.exc
                    frame['protocol_stack'] = []
                    self.value_to_list(frame['protocol_stack'], f.msg.get_value())
                    frame_list.append(frame)
        return frame_list
