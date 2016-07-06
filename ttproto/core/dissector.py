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

from ttproto.core.exceptions import Error
from ttproto.core.data import Data, Message
from ttproto.core.list import ListValue
from ttproto.core.packet import Value, PacketValue
from ttproto.core.typecheck import *
from ttproto.core.lib.all import *
from ttproto.core.lib.ports.pcap import PcapReader
from ttproto.core.lib.inet.meta import InetPacketValue

from collections import OrderedDict


__all__ = [
    'Frame',
    'Dissector'
]


def is_protocol(arg):
    """
    Check if a parameter is a valid protocol.
    This function is used for the typechecker decorator.

    :return: True if a valid protocol, False if not
    :rtype: bool
    """
    return all((
        arg is not None,
        type(arg) == type,
        arg in Dissector.get_implemented_protocols()
    ))


def is_layer_value(arg):
    """
    Check if a parameter is a valid layer value.
    This function is used for the typechecker decorator.

    :return: True if a valid layer value, False if not
    :rtype: bool
    """
    return all((
        arg is not None,
        isinstance(arg, Value)
    ))


class ProtocolNotFound(Error):
    """
    Error thrown when a protocol isn't found in a frame
    """
    pass


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
        :type pcap_frame: (float, Message, Exception)
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

    @typecheck
    def __contains__(self, protocol: is_protocol) -> bool:
        """
        Put the 'in' keyword to check if a protocol is contained in frame

        :param protocol:  Protocol to check
        :type protocol: type

        :raises TypeError: If protocol is not a valid protocol class

        :return: True if the protocol is in the protocol stack of the frame
        :rtype: bool
        """

        # Check the protocol is one entered
        # if protocol not in Dissector.get_implemented_protocols():
        #     raise TypeError(protocol.__name__ + ' is not a protocol class')

        # Get current value
        value = self.__msg.get_value()

        # Parse the whole protocol stack
        while True:

            # If the protocol is contained into it
            if isinstance(value, protocol):
                return True

            # Go to the next layer
            try:
                value = value['pl']
                continue

            # If none found, leave the loop
            except (KeyError, TypeError):
                pass
            break

        # Protocol not found into it
        return False

    @typecheck
    def __repr__(self) -> str:
        """
        Little function to display a frame object

        :return: A string representing this frame object
        :rtype: str
        """
        return "<Frame %3d: %s>" % (self.__id, self.__msg.summary())

    @classmethod
    @typecheck
    def create_list(cls, pcap_frames: PcapReader) -> list_of(this_class):
        """
        The dissector tool initialisation which receives a PcapReader object

        :param pcap_frames: The frames got from pcap using the PcapReader
        :type pcap_frames: PcapReader

        :return: A list of Frame objects
        :rtype: [Frame]

        .. note:: Can't put the typecheck as list of a class into itself
        """
        return list(cls(i, f) for i, f in zip(itertools.count(1), pcap_frames))

    @classmethod
    @typecheck
    def filter_frames(
        cls,
        frames: list_of(this_class),
        protocol: is_protocol
    ) -> (list_of(this_class), list_of(this_class)):
        """
        Allow to filter frames on a protocol

        :param frames: The frames to filter
        :param protocol:  Protocol class for filtering purposes
        :type frames: [Frame]
        :type protocol: type

        :raises TypeError: If protocol is not a protocol class
                           or if the list contains a non Frame object

        :return: A tuple containing the filtered frames and the ignored ones
        :rtype: ([Frame], [Frame])
        """

        # The return list
        filtered_frames = []
        ignored_frames = []

        # Check the protocol is one entered
        if protocol not in Dissector.get_implemented_protocols():
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        # Remove all frames which doesn't include this protocol
        for frame in frames:

            # If an element of the list isn't a Frame
            if not isinstance(frame, Frame):
                raise TypeError('Parameter frames contains a non Frame object')

            # If the protocol is contained into this frame
            if protocol in frame:
                filtered_frames.append(frame)
            else:
                ignored_frames.append(frame)

        # Return the newly created list
        return filtered_frames, ignored_frames

    @typecheck
    def value_to_list(
        self,
        l: list,
        value: Value,
        extra_data: optional(str) = None,
        layer_dict: optional(dict) = None,
        is_option: optional(bool) = False
    ):
        """
        An utility function to parse recursively packet datas

        :param l: The list in which we put the values parsed
        :param value: The value to store
        :param extra_data: The name of the field to save value into dict
        :param layer_dict: The dict in which we will write the value
        :param is_option: To know if the value to write is an option one or not
        :type l: list
        :type value: Value
        :type extra_data: str
        :type layer_dict: dict
        :type is_option: bool
        """

        # Points to packet
        if isinstance(value, PacketValue):

            # Prepare the storage dict
            od = OrderedDict()

            # If an option
            if is_option:
                od['Option'] = value.get_variant().__name__

            # If a protocol value
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

    @typecheck
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

    @typecheck
    def summary(self) -> (int, str):
        """
        Allow a Frame to generate its summary

        :return: Summary of this frame
        :rtype: (int, str)
        """
        if self.__summary is None:
            self.__summary = (self.__id, self.__msg.summary())
        return self.__summary

    @typecheck
    def is_malformed(self) -> bool:
        """
        Check if a frame is malformed or not

        :return: True if this frame is malformed, False if not
        :rtype: bool
        """
        return (self.__error is not None)

    @typecheck
    def __getitem__(self, prot: is_protocol) -> is_layer_value:
        """
        Get the requested informations of the layer level for this frame

        :param prot: The layer level that we want to retrieve
        :type prot: type

        :return: The layer level as a Value instance
        :rtype: Value
        """

        # Check that the layer is a correct protocol
        if prot not in Dissector.get_implemented_protocols():
            raise TypeError(prot.__name__ + ' is not a protocol class')

        # Get current value
        value = self.__msg.get_value()

        # Parse the whole protocol stack
        while True:

            # If we arrive at the correct layer
            if isinstance(value, prot):
                return value

            # Go to the next layer
            try:
                value = value['pl']
                continue

            # If none found, leave the loop
            except (KeyError, TypeError):
                pass
            break

        # If this protocol isn't found in the stack
        raise ProtocolNotFound(
            "%s protocol wasn't found in this frame" % prot.__name__
        )

    @typecheck
    def get_timestamp(self) -> float:
        return self.__timestamp

    @typecheck
    def get_value(self) -> is_layer_value:
        return self.__msg.get_value()


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
        self.__filename = filename

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
    def summary(
        self,
        protocol: optional(is_protocol) = None
    ) -> list_of((int, str)):
        """
        The summaries function to get the summary of frames

        :param protocol: Protocol class for filtering purposes
        :type protocol: type

        :raises TypeError: If protocol is not a protocol class
        :raises PcapError: If the provided file isn't a valid pcap file

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
        .. note:: With the protocol option we can filter
        """

        # Check the protocol is one entered
        # if all((
        #     protocol is not None,
        #     protocol not in Dissector.get_implemented_protocols()
        # )):
        #     raise TypeError(protocol.__name__ + ' is not a protocol class')

        # Prepare the response object
        response = []

        # Disable the name resolution in order to improve performances
        with Data.disable_name_resolution():

            # Read the file and get an iterator on it
            frames = Frame.create_list(PcapReader(self.__filename))

            # Filter the frames for the selected protocol
            if protocol is not None:
                frames, _ = Frame.filter_frames(frames, protocol)

            # Then append the summaries
            for frame in frames:
                response.append(frame.summary())

        # Give the response back
        return response

    @typecheck
    def dissect(
        self,
        protocol: optional(is_protocol) = None
    ) -> list_of(OrderedDict):
        """
        The dissect function to dissect a pcap file into list of frames

        :param protocol: Protocol class for filtering purposes
        :type protocol: type

        :raises TypeError: If protocol is not a protocol class
        :raises PcapError: If the provided file isn't a valid pcap file

        :return: A list of Frame represented as API's dict form
        :rtype: [OrderedDict]
        """

        # Check the protocol is one entered
        if all((
            protocol is not None,
            protocol not in Dissector.get_implemented_protocols()
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        # Create the frame list
        frame_list = []

        # For speeding up the process
        with Data.disable_name_resolution():

            # Get the list of frames
            frames = Frame.create_list(PcapReader(self.__filename))

            # Filter the frames for the selected protocol
            if protocol is not None:
                frames, _ = Frame.filter_frames(frames, protocol)

            # Then append them in the frame list
            for frame in frames:
                frame_list.append(frame.dict())

        # Then return the frame list
        return frame_list


if __name__ == "__main__":
    # dis = Dissector(
    #     'tests/test_dumps/TD_COAP_CORE_07_FAIL_No_CoAPOptionContentFormat_plus_random_UDP_messages.pcap'
    # )
    # print(dis.summary())
    # print('##### Dissect without filtering #####')
    # print(dis.dissect())
    # print('#####')
    # print('#####')
    # print('#####')
    # print('##### Dissect without filtering on CoAP #####')
    # print(dis.dissect(CoAP))
    # print('#####')
    # print(Dissector.get_implemented_protocols())
    # frame_list = Frame.create_list(PcapReader(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'TD_COAP_CORE_07_FAIL_No_CoAPOptionContentFormat_plus_random_UDP_messages.pcap'
    #     ))
    # ))
    # frame_list, _ = Frame.filter_frames(frame_list, CoAP)
    # print(frame_list[0].get_layer(IPv4))
    # print(frame_list[0].get_timestamp())
    # print(frame_list[0].get_value())
    # print(frame_list[0]['CoAP'])
    # print(frame_list[0]['CoAP']['Type'])
    # try:
    #     print(frame_list[0][Value])
    # except InputParameterError:
    #     pass
    # try:
    #     print(frame_list[0][IPv6])
    # except ProtocolNotFound as e:
    #     print(e)
    # print(frame_list[0][CoAP])
    # print(frame_list[0][CoAP]['type'])
    # print(frame_list[0]['Unknown'])
    pass
