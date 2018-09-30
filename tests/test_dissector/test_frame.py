import unittest

from collections import OrderedDict
from ttproto.core.dissector import Capture, Dissector, Frame, ReaderError
from ttproto.core.lib.all import *
from tests.test_tools.struct_validator import StructureValidator
from ttproto.core.packet import Value, PacketValue
from ttproto.core.lib.inet.meta import InetPacketValue
from ttproto.core.typecheck3000 import InputParameterError


class FrameTestCase(unittest.TestCase):
    """
    Test class for the Frame object
    """

    # #################### Tests parameters #########################

    # File path
    TEST_FILE_DIR = 'tests/test_dumps'
    PCAP_FILE = TEST_FILE_DIR + '/coap/CoAP_plus_random_UDP_messages.pcap'

    # Create a struct checker object
    struct_validator = StructureValidator()
    FRAMES_PROTOCOL = {
        1: [
            UDP,
            IPv4,
            NullLoopback
        ],
        2: [
            UDP,
            IPv4,
            NullLoopback
        ],
        3: [
            IPv4,
            NullLoopback
        ],
        4: [
            UDP,
            IPv4,
            NullLoopback,
            CoAP
        ],
        5: [
            UDP,
            IPv4,
            NullLoopback,
            CoAP
        ]
    }
    FRAME_VALUES = {
        'id': int,
        'ts': float,
        'error': Exception,
        'value': Value
    }

    # #################### Utility functions #########################

    def list_diff(self, list1, list2):
        return_list = []
        for el in list2:
            if el not in list1:
                return_list.append(el)
        return return_list

    def frames_with_protocol(self, protocol):
        frames_with_this_protocol = []
        for frame_prot in self.FRAMES_PROTOCOL:
            if protocol in self.FRAMES_PROTOCOL[frame_prot]:
                frames_with_this_protocol.append(frame_prot)
        return frames_with_this_protocol

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the frame list from the valid pcap file
        """
        self.frames = Capture(self.PCAP_FILE).frames

    # #################### Tests functions #########################

    # ##### __repr__
    def test___repr__(self):

        # Check the str representation
        for frame in self.frames:
            self.assertEqual(type(str(frame)), str)
            self.assertEqual(type(repr(frame)), str)
            self.assertGreater(len(str(frame)), 0)
            self.assertGreater(len(repr(frame)), 0)

    # ##### summary
    def test_summary(self):

        # Check the str representation
        counter = 1
        for frame in self.frames:

            # Get the summary
            summary = frame.summary()

            # Check summary structure
            self.assertIsNotNone(summary)
            self.assertEqual(type(summary), tuple)
            self.assertEqual(len(summary), 2)

            # Check first element
            self.assertEqual(type(summary[0]), int)
            self.assertEqual(summary[0], counter)

            # Check second element
            self.assertEqual(type(summary[1]), str)
            self.assertGreater(len(summary[1]), 0)

            # Increment counter
            counter += 1

    # ##### dict
    def test_dict(self):

        # Check the str representation
        for frame in self.frames:

            # Get the dictionnary
            dictionnary = frame.dict()

            # Check dictionnary structure
            self.assertIsNotNone(dictionnary)
            self.assertEqual(type(dictionnary), OrderedDict)
            self.assertEqual(len(dictionnary), 5)

            # Check whole structure from struct checker
            self.struct_validator.check_frame(dictionnary)

    # ##### __contains__
    def test___contains__(self):

        # Check the provided structure
        self.assertEqual(len(self.FRAMES_PROTOCOL), len(self.frames))

        # Get all the protocols
        protocols = Dissector.get_implemented_protocols()

        # Check that the protocols are in the correct frame
        i = 1
        for frame in self.frames:

            # Get the elements that shouldn't be in it
            should_not_be = self.list_diff(self.FRAMES_PROTOCOL[i], protocols)

            # Check that those which shouldn't be present really aren't
            for non_present in should_not_be:
                self.assertNotIn(non_present, frame)

            # Check that those which are present really are
            for prot in self.FRAMES_PROTOCOL[i]:
                self.assertIn(prot, frame)

            # Increment counter
            i += 1

    def test___contains__none(self):

        # Check that the protocols are in the correct frame
        for frame in self.frames:

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = None in frame

    def test___contains__not_a_protocol(self):

        # Check that the protocols are in the correct frame
        for frame in self.frames:

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = Frame in frame

    def test___contains__higher_classes(self):

        # Check that the protocols are in the correct frame
        for frame in self.frames:

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = InetPacketValue in frame

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = PacketValue in frame

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = Value in frame

    # ##### filter_frames
    def test_filter_frames(self):

        # Get all the protocols
        protocols = Dissector.get_implemented_protocols()

        # Filter on each protocol
        for protocol in protocols:

            # Filter on each protocol
            filtered, ignored = Frame.filter_frames(self.frames, protocol)

            # Get the id of frames with this protocol
            ids = self.frames_with_protocol(protocol)

            # Check the two datas received
            self.assertEqual(type(filtered), list)
            for f in filtered:
                self.assertEqual(type(f), Frame)
            self.assertEqual(type(ignored), list)
            for i in ignored:
                self.assertEqual(type(i), Frame)
            self.assertEqual(len(filtered) + len(ignored), len(self.frames))

            # Check the length of filtered
            self.assertEqual(len(filtered), len(ids))

            # Check that each element goes together
            for frame in filtered:
                dictionnary = frame.dict()
                self.assertIn(dictionnary['id'], ids)

    def test_filter_frames_none_type(self):

        # Filter on none protocol
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(self.frames, type(None))

    def test_filter_frames_none(self):

        # Filter on none protocol
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(self.frames, None)

    def test_filter_frames_not_a_protocol(self):

        # Filter on each protocol
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(self.frames, Frame)

    def test_filter_frames_higher_classes(self):

        # Filter on each protocol
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(
                self.frames,
                InetPacketValue
            )
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(self.frames, PacketValue)
        with self.assertRaises(InputParameterError):
            filtered, ignored = Frame.filter_frames(self.frames, Value)

    def test_filter_frames_only_single_frame(self):

        # Get all the protocols
        protocols = Dissector.get_implemented_protocols()

        # Filter on each protocol
        for protocol in protocols:

            # Filter on none protocol
            with self.assertRaises(InputParameterError):
                filtered, ignored = Frame.filter_frames(
                    self.frames[0],
                    protocol
                )

    def test_filter_frames_list_of_non_frame(self):

        # Get all the protocols
        protocols = Dissector.get_implemented_protocols()

        # Filter on each protocol
        for protocol in protocols:

            # Filter on none protocol
            with self.assertRaises(TypeError):
                filtered, ignored = Frame.filter_frames(protocols, protocol)

    def test_filter_frames_list_of_frame_with_a_non_frame(self):

        # Get all the protocols
        protocols = Dissector.get_implemented_protocols()

        # Insert a non frame object
        self.frames.insert(1, protocols[1])

        # Filter on each protocol
        for protocol in protocols:

            # Filter on none protocol
            with self.assertRaises(TypeError):
                filtered, ignored = Frame.filter_frames(self.frames, protocol)

    # ##### __getitem__
    def test___getitem__values(self):

        # For each value name, check its type
        for value_name, value_type in self.FRAME_VALUES.items():

            if value_name != 'error':
                for frame in self.frames:
                    self.assertIsInstance(frame[value_name], value_type)
            else:  # 'error' field can be None
                for frame in self.frames:
                    if frame[value_name]:
                        self.assertIsInstance(frame[value_name], value_type)

    def test___getitem__unknown_value(self):

        for frame in self.frames:
            with self.assertRaises(AttributeError):
                test = frame['unknown']

    def test___getitem__none(self):
        for frame in self.frames:
            with self.assertRaises(InputParameterError):
                test = frame[None]

    def test___getitem__type_but_not_a_protocol(self):

        # Check that the protocols are in the correct frame
        for frame in self.frames:

            # Expect the exception
            with self.assertRaises(InputParameterError):
                test = frame[Frame]

    def test___getitem__higher_classes(self):

        # Check that the protocols are in the correct frame
        for frame in self.frames:

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = frame[InetPacketValue]

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = frame[PacketValue]

            # Expect the exception
            with self.assertRaises(InputParameterError):
                check = frame[Value]


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
