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


from collections import OrderedDict
from os import path
import logging
import re

from ttproto.core.exceptions import Error, ReaderError, UnknownField
from ttproto.core.data import Data, Message
from ttproto.core.list import ListValue
from ttproto.core.packet import Value, PacketValue
from ttproto.core.typecheck import typecheck, list_of, optional, anything, either
from ttproto.core.lib.all import *
from ttproto.core.lib.inet.meta import InetPacketValue
from ttproto.core.lib.readers.pcap import PcapReader

log = logging.getLogger('[dissection]')
log.propagate = True  # so AMQP handler (if attached by ancestor) emits logs into the bus
log.setLevel(level=logging.WARNING)

__all__ = [
    'get_dissectable_protocols',
    'is_protocol',
    'is_layer_value',
    'ProtocolNotFound',
    'Frame',
    'Dissector',
    'Capture',
]


def add_subclass(impl_list, new_class):
    subclasses = new_class.__subclasses__()
    # print(new_class.__name__ + ':')
    # print(subclasses)
    impl_list += subclasses
    # print('#####################')
    for subclass in subclasses:
        add_subclass(impl_list, subclass)


@typecheck
def get_dissectable_protocols() -> list_of(type):
    """
    Return list of the implemented protocols (PacketValue classes)
    :return: Implemented protocols
    :rtype: [type]
    """
    # Just directly get the PacketValue and InetPacketValue subclasses
    implemented_protocols = []
    add_subclass(implemented_protocols, PacketValue)
    # Remove the InetPacketValue class
    implemented_protocols.remove(InetPacketValue)
    return implemented_protocols


@typecheck
def is_protocol(arg: anything) -> bool:
    """
    Check if a parameter is a valid protocol.
    This function is used for the typechecker decorator.

    :param arg: The object to check
    :type arg: anything

    :return: True if a valid protocol, False if not
    :rtype: bool
    """
    return all((
        arg is not None,
        type(arg) == type,
        arg in get_dissectable_protocols()
    ))


@typecheck
def is_layer_value(arg: anything) -> bool:
    """
    Check if a parameter is a valid layer value.
    This function is used for the typechecker decorator.

    :param arg: The object to check
    :type arg: anything

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
        log.debug("[Frame Init] New Frame id: %d" % id)

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
        if not is_protocol(protocol):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

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
            except (KeyError, TypeError, UnknownField):
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

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def message(self):
        return self.__msg

    @property
    def error(self):
        return self.__error

    # @typecheck
    def __value_to_list(
            self,
            l: list,
            value: Value,
            extra_data: optional(str) = None,
            layer_dict: optional(dict) = None,
            is_option: optional(bool) = False
    ):
        """
        An utility function to parse recursively packets' data

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
        try:
            # Points to packet
            # print("dissecting value: " + str(value) + " || type : " + str(type(value)))
            if isinstance(value, PacketValue):

                # Prepare the storage dict
                od = OrderedDict()

                # If an option
                if is_option:
                    od['Option'] = value.get_variant().__name__

                # If a protocol value
                else:
                    # log.debug(' Protocol header:  ' + str(value.get_variant().__name__))
                    od['_type'] = 'protocol'
                    od['_protocol'] = value.get_variant().__name__

                l.append(od)

                i = 0
                for f in value.get_variant().fields():
                    self.__value_to_list(l, value[i], f.name, od)
                    i += 1

            # Points to list value
            elif isinstance(value, ListValue):

                prot_options = []
                for i in range(0, len(value)):
                    self.__value_to_list(prot_options, value[i], is_option=True)
                # log.debug(' options:    || value : ' + str(prot_options))
                layer_dict['Options'] = prot_options

            # If it's a single field
            else:
                # log.debug(' field:  ' + str(extra_data) + '|| value : ' + str(value))
                layer_dict[extra_data] = str(value)

        except TypeError as e:
            # log.error(e.__traceback__)
            log.error(e, exc_info=True)
            log.error(
                'extra_data:  ' + str(extra_data) + '|| value : ' + str(value) + '|| layerDict : ' + str(layer_dict))

    @typecheck
    def dict(self) -> OrderedDict:
        """
        Allow a Frame to generate an ordered dict from its values

        :return: A representation of this frame object as an OrderedDict
        :rtype: OrderedDict
        """
        if self.__dict is None:
            # Create its dictionary representation
            self.__dict = OrderedDict()

            # Put the values into it
            self.__dict['_type'] = 'frame'
            self.__dict['id'] = self.__id
            self.__dict['timestamp'] = self.__timestamp
            self.__dict['error'] = self.__error
            self.__dict['protocol_stack'] = []
            self.__value_to_list(
                self.__dict['protocol_stack'],
                self.__msg.get_value()
            )
        # Return it
        return self.__dict

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
        if not is_protocol(protocol):
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
    def summary(self) -> (int, str):
        """
        Allow a Frame to generate its summary

        :return: Summary of this frame
        :rtype: (int, str)
        """
        if self.__summary is None:
            one_line_msg_descriptiion = self.__msg.summary()
            # delete more that one consecutive space
            re.sub("\s\s+", " ", one_line_msg_descriptiion)
            self.__summary = (self.__id, one_line_msg_descriptiion)
        return self.__summary

    @typecheck
    def __getitem__(
            self,
            item: either(is_protocol, str)
    ) -> either(int, float, optional(Exception), str, is_layer_value):
        """
        Get the requested informations of the layer level for this frame. This
        function is also used to retrieve flat informations like src, dst, ...

        :param prot: The layer level or information that we want to retrieve
        :type prot: either(type, str)

        :return: The layer level or the information as a Value instance
        :rtype: Value

        .. seealso:: modules :ttproto:core:data:`̀MessageDescription
        """

        # If a single string, fetch the flat informations
        if isinstance(item, str):

            # If one that we get from pcap header
            if item == 'id':
                return self.__id
            elif item == 'ts':
                return self.__timestamp
            elif item == 'error':
                return self.__error
            elif item == 'value':
                return self.__msg.get_value()

            # If another one, try to get it from MessageDescription
            else:

                # Get the message description with values stored as attributes
                md = self.__msg.get_description()

                try:
                    value = getattr(md, item)
                except AssertionError:
                    raise AttributeError(
                        "%s information was not found into this frame" % item
                    ) from None  # From None suppress the first exception

                return value

        # If a protocol, fetch the layer value
        else:
            # Check that the layer is a correct protocol
            if not is_protocol(item):
                raise TypeError(item.__name__ + ' is not a protocol class')

            # Get current value
            value = self.__msg.get_value()

            # Parse the whole protocol stack
            while True:

                # If we arrive at the correct layer
                if isinstance(value, item):
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
                "%s protocol wasn't found in this frame" % item.__name__
            )


class Dissector:
    """
        Class for the dissector tool
    """

    # Class variables
    __implemented_protocols = None
    __capture = None

    @typecheck
    def __init__(self, filename: str):
        """
        The dissector tool initialisation which receives a filename

        :param filename: Filename of the pcap file to be dissected
        :type filename: str
        """

        # Get the capture of the file
        self.__capture = Capture(filename)
        logging.warning("Deprication of Dissector class and its API in favour of Capture's")

    @classmethod
    @typecheck
    def get_implemented_protocols(cls) -> list_of(type):
        """
        Allow to get the implemented protocols

        :return: Implemented protocols
        :rtype: [type]
        """
        logging.warning("Deprecation warning in favour of package's get_dissectable_protocols method!")
        # Singleton pattern
        if cls.__implemented_protocols is None:
            # Just directly get the PacketValue and InetPacketValue subclasses
            cls.__implemented_protocols = []
            # cls.__implemented_protocols += PacketValue.__subclasses__()
            # cls.__implemented_protocols += InetPacketValue.__subclasses__()

            # NOTE: This may ben needed if we change the protocol getter system
            add_subclass(cls.__implemented_protocols, PacketValue)

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

        :Example:

        from ttproto.core.lib.all import Ieee802154

        for s in dissector.summary(protocol = Ieee802154):

            print(s)

        :raises TypeError: If protocol is not a protocol class
        :raises ReaderError: If the reader couldn't process the file

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

        # Check the protocol
        if all((
                protocol,
                not is_protocol(protocol)
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        # Disable the name resolution in order to improve performances
        with Data.disable_name_resolution():

            # Get the frames from the capture
            frames = self.__capture.frames

            # Filter the frames for the selected protocol
            if protocol is not None:
                frames, _ = Frame.filter_frames(frames, protocol)

        # Then give the summary of every frames
        return [frame.summary() for frame in frames]

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
        :raises ReaderError: If the reader couldn't process the file

        :return: A list of Frame represented as API's dict form
        :rtype: [OrderedDict]
        """
        # log.debug('Starting dissection.')
        # Check the protocol is one entered
        if all((
                protocol,
                not is_protocol(protocol)
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        # For speeding up the process
        with Data.disable_name_resolution():

            # Get the list of frames
            frames = self.__capture.frames

            # Filter the frames for the selected protocol
            if protocol is not None:
                frames, _ = Frame.filter_frames(frames, protocol)

        # Then return the list of dictionary frame representation
        return [frame.dict() for frame in frames]


class Capture:
    """
    Class representing a Capture got from a file.

    It will give the following attributes to the users:
        - filename  => Name of the file from which the Capture was generated
        - frames  => The frame list generated
        - malformed  => The malformed frames that we didn't manage to decode

    .. note::
        The Capture object has a dictionnary of Readers in function of their
        extension
    """

    reader_extension = {
        '.pcap': PcapReader,
        '.dump': PcapReader,
        # 'json': JsonReader  # NOTE: An idea for later
    }

    @typecheck
    def __init__(self, filename: str):
        """
        Initialize a capture from .pcap filename

        :param filename: The .pcap file of the network traces capture
        :type filename: str
        """
        self._filename = filename
        self._frames = None
        self._malformed = None

        # dissect pcap capture
        self.__process_file()

    @property
    def filename(self):
        return self._filename

    @property
    def frames(self):
        if not self._frames:
            self.__process_file()
        return self._frames

    @property
    def malformed(self):
        if not self._malformed:
            self.__process_file()
        return self._malformed

    def __process_file(self):
        """
        The Capture function to decode the file into a list of frames

        :raises ReaderError: If the file was not found or if no reader matched

        .. note:: Here, we will get the reader in function of the extension
        """

        # Get the reader in function of the extension
        name, extension = path.splitext(self._filename)
        try:
            reader = self.reader_extension[extension]
        except KeyError:
            raise ReaderError(
                'No reader could be matched with %s extension' % extension
            )

        # Get an iterable reader for generating frames
        try:
            iterable_reader = reader(self._filename)
        except IOError as e:
            print("PCAP file not found. You sure %s exists? \n" % self._filename)
            raise e
        except Exception as e:
            raise ReaderError(
                "The reader wans't able to generate the frames \n" + str(e)
            ) from e  # Raise this exception from the

        # Initialize the list attributes
        self._frames = []
        self._malformed = []

        # Iterate over those tuples to generate the frames
        for count, ternary_tuple in enumerate(iterable_reader, 1):

            # The format of ternary tuple is the following:
            #   - Timestamp represented as a float
            #   - The Message object associated to the frame
            #   - An Exception if one occured, None if everything went fine

            # If not malformed (ie no exception)
            if not ternary_tuple[2]:
                self._frames.append(Frame(count, ternary_tuple))

            # If malformed
            else:
                self._frames.append(Frame(count, ternary_tuple))

    @typecheck
    def get_dissection(
            self,
            protocol: optional(is_protocol) = None,
    ) -> list_of(OrderedDict):
        """
        Function to get dissection of a capture as a list of frames represented as strings

        :param protocol: Protocol class for filtering purposes
        :type protocol: type
        :raises TypeError: If protocol is not a protocol class
        :raises ReaderError: If the reader couldn't process the file

        :return: A list of Frame represented as API's dict form
        :rtype: [OrderedDict]

        """
        # log.debug('Starting dissection.')
        # Check the protocol is one entered
        if all((
                protocol,
                not is_protocol(protocol)
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        fs = self.frames

        # For speeding up the process
        with Data.disable_name_resolution():

            # Filter the frames for the selected protocol
            if protocol:
                fs, _ = Frame.filter_frames(fs, protocol)

        if fs is None:
            raise Error('Empty capture cannot be dissected')

        # Then return the list of dictionary frame representation
        return [frame.dict() for frame in fs]

    @typecheck
    def get_dissection_simple_format(
            self,
            protocol: optional(is_protocol) = None,
    ) -> list_of(str):
        """
        Function to get dissection of a capture as a list of frames represented as strings

        :param protocol: Protocol class for filtering purposes
        :type protocol: type
        :raises TypeError: If protocol is not a protocol class
        :raises ReaderError: If the reader couldn't process the file

        :return: A list of Frame represented as plain non-structured text
        :rtype: [str]

        """
        # log.debug('Starting dissection.')
        # Check the protocol is one entered
        if all((
                protocol,
                not is_protocol(protocol)
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        fs = self.frames

        # For speeding up the process
        with Data.disable_name_resolution():

            # Filter the frames for the selected protocol
            if protocol:
                fs, _ = Frame.filter_frames(fs, protocol)

        if fs is None:
            raise Error('Empty capture cannot be dissected')

        # fixme modify Message class from ttproto.data structure so I can get text display wihtout this patch
        class WritableObj(object):
            def __init__(self, text=''):
                self.val = text

            def __str__(self):
                return self.val

            def write(self, text):
                self.val += text

        frame_dissection_list = []

        for f in fs:
            text_output = WritableObj()
            f.message.display(
                output=text_output
            )
            frame_dissection_list.append(str(text_output))

        # Then return the list of frames,each as a simple text dissection
        return frame_dissection_list

    @typecheck
    def summary(
            self,
            protocol: optional(is_protocol) = None
    ) -> list_of((int, str)):
        """
        The summaries function to get the summary of frames

        :param protocol: Protocol class for filtering purposes
        :type protocol: type

        :Example:

        from ttproto.core.lib.all import Ieee802154

        for s in dissector.summary(protocol = Ieee802154):

            print(s)

        :raises TypeError: If protocol is not a protocol class
        :raises ReaderError: If the reader couldn't process the file

        :return: Basic informations about frames like the underlying example
        :rtype: [(int, str)]

        :Example:

            [
                (13, '[127.0.0.1 -> 127.0.0.1] CoAP [CON 38515] GET /test'),

                (14, '[127.0.0.1 -> 127.0.0.1] CoAP [ACK 38515] 2.05 Content'),

                (21, '[127.0.0.1 -> 127.0.0.1] CoAP [CON 38516] PUT /test'),

                (22, '[127.0.0.1 -> 127.0.0.1] CoAP [ACK 38516] 2.04 Changed')]
            ]

        .. note:: With the protocol option we can filter the response
        """

        if all((
                protocol,
                not is_protocol(protocol)
        )):
            raise TypeError(protocol.__name__ + ' is not a protocol class')

        fs = self.frames

        # For speeding up the process
        with Data.disable_name_resolution():

            # Filter the frames for the selected protocol
            if protocol:
                fs, _ = Frame.filter_frames(fs, protocol)

        if fs is None:
            raise Error('Empty capture cannot be dissected')

        # Return list of frames summary
        return [frame.summary() for frame in fs]


if __name__ == "__main__":
    import json
    import logging

    cap = Capture(
        #    'tests/test_dumps/DissectorTests/coap/CoAP_plus_random_UDP_messages.pcap'
        'tests/test_dumps/coap/CoAP_plus_random_UDP_messages.pcap'
        # 'tmp/frame2_onem2m.pcap'
        # 'tmp/frame1_onem2m.pcap'
    )
    dis = cap.get_dissection_simple_format()
    # for i in dis:
    #     print(i)
    #     print('\n' * 2)
    #
    # print('********' * 2)

    # print(cap.summary())
    # print('#####')
    # print(cap.summary())
    # print('##### Dissect with filtering on CoAP #####')
    # print(cap.get_dissection(CoAP))
    # print('#####')
    # print('##### Dissect without filtering #####')
    # print(json.dumps(cap.get_dissection(), indent=4))
    # print('#####')
    # print('#####')
    # print(Dissector.get_implemented_protocols())
    # capture = Capture('/'.join((
    #     'tests',
    #     'test_dumps',
    #     'TD_COAP_CORE_02_MULTIPLETIMES.pcap'
    # )))
    # try:
    #     capt = Capture('/'.join((
    #         'tests',
    #         'test_dumps',
    #         'NON_EXISTENT.pcap'
    #     )))
    #     capt.frames
    # except ReaderError:
    #     print('File not found correctly managed')
    # try:
    #     capt = Capture('/'.join((
    #         'tests',
    #         'test_files',
    #         'WrongFilesForTests',
    #         'not_a_pcap_file.dia'
    #     )))
    #     capt.frames
    # except ReaderError:
    #     print('Reader not found correctly managed')
    # try:
    #     capt = Capture('/'.join((
    #         'tests',
    #         'test_files',
    #         'WrongFilesForTests',
    #         'empty_pcap.pcap'
    #     )))
    #     capt.frames
    # except ReaderError:
    #     print('Reader error correctly managed (empty file)')
    # try:
    #     capture.frames = []
    # except AttributeError:
    #     print('Writting capture frames correctly blocked')
    # try:
    #     capture.malformed = []
    # except AttributeError:
    #     print('Writting capture malformed frames correctly blocked')
    # try:
    #     capture.filename = ''
    # except AttributeError:
    #     print('Writting capture filename correctly blocked')
    # print('##### Frames')
    # print(capture.frames)
    # print('##### Malformed')
    # print(capture.malformed)
    # print('##### Second time Frames')
    # print(capture.frames)
    # print('##### Second time Malformed')
    # print(capture.malformed)
    # frame_list = Capture(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'TD_COAP_CORE_07_FAIL_No_CoAPOptionContentFormat_plus_random_UDP_messages.pcap'
    #     ))
    # ).frames
    # frame_list, _ = Frame.filter_frames(frame_list, CoAP)
    # print(frame_list[0]['value'])
    # print(frame_list[0][IPv4])
    # print(frame_list[0]['ts'])
    # print(frame_list[0]['value'])
    # print(frame_list[0][CoAP])
    # print(frame_list[0][CoAP]['Type'])
    # try:
    #     print(frame_list[0][Value])
    # except InputParameterError:
    #     pass
    # try:
    #     print(frame_list[0][IPv6])
    # except ProtocolNotFound as e:
    #     print(e)
    # for f in frame_list:
    #     if CoAP in f:
    #         print(f[CoAP])
    #         print(f[CoAP]['type'])
    #         print(f[CoAP]['pl'])
    #         print(f['id'])
    #         print(f['ts'])
    #         print(f['error'])
    #         print(f['src'])
    #         print(f['dst'])
    #         print(f['hw_src'])
    #         print(f['hw_dst'])
    #         print(f['src_port'])
    #         print(f['dst_port'])
    # for frame in frame_list:
    #     try:
    #         print(frame[CoAP]['opt'][CoAPOptionMaxAge]['val'])
    #     except KeyError:
    #         pass
    # try:
    #     print(frame_list[0]['Unknown'])
    # except AttributeError:
    #     print('Fetching an unknown attribute correclty throw an error')
    # frame_list = Capture(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'wireshark_official_6lowpan_sample.pcap'
    #     ))
    # ).frames
    # frame_list = Capture(
    #     '/'.join((
    #         'tests',
    #         'test_dumps',
    #         'www.cloudshark.org_captures_46a9a369e6a9.pcap'
    #     ))
    # ).frames
    # frame_list, ignored = Frame.filter_frames(frame_list, Ethernet)
    # print('The frame list contains %d elements:' % len(frame_list))
    # c = 0
    # for f in frame_list:
    #     print('%d: %s' % (c, f['value']))
    #     c += 1
    # c = 0
    # for i in ignored:
    #     print('%d: %s' % (c, i['value']))
    #     c += 1
    # pass
