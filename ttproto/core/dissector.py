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
import sys
import inspect
import ttproto.core.lib.all

from ttproto.core.data import Data, Message
from ttproto.core.packet import Value, PacketValue
from ttproto.core.list import ListValue
from ttproto.core.typecheck import *
from ttproto.core.lib.ports.pcap import PcapReader
from ttproto.core.lib.inet.meta import InetPacketValue

from collections import OrderedDict


__all__ = [
    'Frame',
    'Dissector'
]


class Frame:
    """
        Class to represent a frame object
    """

    @typecheck
    def __init__(
        self,
        id: int,
        pcap_frame: (float, Message, optional(Exception))
    ):
        """
        The init function of the Frame object

        :param id: The id of the current frame
        :param pcap_frame: The frame tuple got from reading the PcapReader
        :type id: int
        :type pcap_frame: tuple(float, Message, Exception)
        """

        # Put the different variables of it
        self.__id = id

        # Get the 3 values of a frame given by the PcapReader
        # ts: Its timestamp value (from the header)
        # msg: Its message read directly from bytes (can be decoded)
        # exc: Exception if one occured
        self.__timestamp, self.__msg, self.__error = pcap_frame

        # Put its dictionnary representation and its summary as not done yet
        self.__dict = None
        self.__summary = None

    def __repr__(self):
        """
        Little function to display a frame object

        :return: A string representing this frame object
        :rtype: str
        """
        return "<Frame %3d: %s>" % (self.__id, self.__msg.summary())

    @classmethod
    @typecheck
    def create_list(cls, pcap_frames: PcapReader) -> list:
        """
        The dissector tool initialisation which receives a filename

        :param pcap_frames: The frames got from pcap using the PcapReader
        :type PcapReader: str

        :return: A list of Frame objects
        :rtype: [Frame]
        """
        return list(cls(i, f) for i, f in zip(itertools.count(1), pcap_frames))

    @typecheck
    def value_to_list(
        self,
        l: list,
        value: Value,
        extra_data: optional(str) = None,
        layer_dict: optional(dict) = None,
        is_option: optional(bool) = False
    ):

        # Points to packet
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

        # Points to list value
        elif isinstance(value, ListValue):
            prot_options = []
            for i in range(0, len(value)):
                self.value_to_list(prot_options, value[i], is_option=True)
            layer_dict['Options'] = prot_options

        # If it's a single field
        else:
            layer_dict[extra_data] = str(value)

    def dict(self) -> OrderedDict:
        """
        Allow a Frame to generate an ordered dict from its values

        :return: A representation of this frame object as an OrderedDict
        :rtype: OrderedDict
        """
        if self.__dict is None:

            # Create its dictionnary representation
            self.__dict = OrderedDict()

            # Put the values into it
            self.__dict['_type'] = 'frame'
            self.__dict['id'] = self.__id
            self.__dict['timestamp'] = self.__timestamp
            self.__dict['error'] = self.__error
            self.__dict['protocol_stack'] = []
            self.value_to_list(
                self.__dict['protocol_stack'],
                self.__msg.get_value()
            )

        # Return it
        return self.__dict

    def summary(self) -> (int, str):
        """
        Allow a Frame to generate its summary

        :return: Summary of this frame
        :rtype: (int, str)
        """
        if self.__summary is None:
            self.__summary = (self.__id, self.__msg.summary())
        return self.__summary


class Dissector:
    """
        Class for the dissector tool
    """

    # Class variables
    __implemented_protocols = None

    @typecheck
    def __init__(self, filename: str):
        """
        The dissector tool initialisation which receives a filename

        :param filename: Filename of the pcap file to be dissected
        :type filename: str
        """

        # Get the reader of the file (this can throw an exception)
        self.__reader = PcapReader(filename)

    @classmethod
    @typecheck
    def get_implemented_protocols(cls) -> list_of(type):
        """
        Allow to get the implemented protocols

        :return: Implemented protocols
        :rtype: [type]
        """

        # Singleton pattern
        if cls.__implemented_protocols is None:

            # # First way to do it, can get name and class objects
            #   The problem is that it takes options classes too
            # for name, obj in inspect.getmembers(sys.modules[__name__]):
            # for name, obj in inspect.getmembers(ttproto.core.lib.inet.all):
            #     if inspect.isclass(obj) and issubclass(obj, PacketValue):
            #         print(name)

            # Just directly get the PacketValue and InetPacketValue subclasses
            cls.__implemented_protocols = []
            cls.__implemented_protocols += PacketValue.__subclasses__()
            cls.__implemented_protocols += InetPacketValue.__subclasses__()

            # Remove the InetPacketValue class
            cls.__implemented_protocols.remove(InetPacketValue)

        # Return the singleton value
        return cls.__implemented_protocols

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
        :rtype: [(int, str)]

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
            # if protocol is CoAP:
            #     selected_frames = [f for f in frames if f.coap]
            # else:
            selected_frames = frames

            for f in selected_frames:
                response.append(f.summary())

            # malformed frames
            # malformed = list (filter ((lambda f: f.exc), frames))
        return response

    @typecheck
    def dissect(
        self,
        protocol: optional(PacketValue) = None
    ) -> list_of(OrderedDict):
        """
        The dissect function to dissect a pcap file into list of frames

        :param filename: filename of the pcap file to be dissected
        :param protocol: protocol class for filtering purposes (inheriting
        from packet Value)
        :return: [OrderedDict]
        """

        # Check the protocol is correct if there's one
        if protocol:
            assert issubclass(protocol, PacketValue)

        # Create the frame list
        frame_list = []

        # For speeding up the process
        with Data.disable_name_resolution():

            # Get the list of frames
            frames = Frame.create_list(self.__reader)

            # Then append them in the frame list
            for frame in frames:
                frame_list.append(frame.dict())

        # Then return the frame list
        return frame_list

if __name__ == "__main__":
    # res = Dissector('tests/test_dumps/TD_COAP_CORE_01_PASS.pcap').dissect()
    # print(res)
    # print(Dissector.get_implemented_protocols())
    pass
