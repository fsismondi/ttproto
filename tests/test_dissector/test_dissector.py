import unittest
import logging
import json
from os import path

from ttproto.core.typecheck3000 import InputParameterError
from tests.test_tools.struct_validator import StructureValidator

from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.meta import InetPacketValue
from ttproto.core.lib.inet.coap import CoAP
from ttproto.core.lib.inet.sixlowpan import SixLowpan
from ttproto.core.dissector import Frame, Capture, ReaderError, get_dissectable_protocols
from ttproto.utils.pcap_filter import openwsn_profile_filter


class CaptureAndDissectionsTestCase(unittest.TestCase):
    """
    Test dissections. Unit testing methods
    """

    # #################### Tests parameters #########################

    # File path
    TEST_FILE_DIR = 'tests/test_dumps'

    # dissect CoAP pcap with other UDP messages:
    PCAP_FILE = path.join(TEST_FILE_DIR, 'coap', 'CoAP_plus_random_UDP_messages.pcap')

    # pcaps that MUST throw exceptions
    WRONG_TEST_FILE_DIR_NAME = 'others'
    EMPTY_PCAP_FILE = path.join(TEST_FILE_DIR, WRONG_TEST_FILE_DIR_NAME, 'empty_pcap.pcap')
    NOT_A_PCAP_FILE = path.join(TEST_FILE_DIR, WRONG_TEST_FILE_DIR_NAME, 'not_a_pcap_file.dia')

    # Create a struct checker object
    struct_validator = StructureValidator()

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the dissector instance
        """
        self.capture = Capture(self.PCAP_FILE)

    # #################### Utilities functions #########################

    def check_summary(self, summary):
        self.assertTrue(type(summary), tuple)
        self.assertEqual(len(summary), 2)
        self.assertTrue(type(summary[0]), int)
        self.assertGreater(summary[0], 0)
        self.assertTrue(type(summary[1]), str)
        self.assertGreater(len(summary[1]), 0)

    # #################### Tests functions #########################

    # ##### get_dissectable_protocols
    def test_get_dissectable_protocols(self):

        # Get implemented protocols and check their values
        implemented_protocols = get_dissectable_protocols()
        self.assertEqual(type(implemented_protocols), list)
        self.assertGreater(len(implemented_protocols), 0)
        for prot in implemented_protocols:
            self.assertTrue(issubclass(prot, PacketValue))

    # ##### summary
    def test_summary_without_filtering(self):

        # Get and check the summary
        summary = self.capture.summary()
        self.assertTrue(type(summary), list)
        self.assertTrue(len(summary), 5)

        i = 1
        for f_sum in summary:
            self.check_summary(f_sum)
            self.assertEqual(f_sum[0], i)
            i += 1

        # Try to get another summary with None provided
        summary_with_none = self.capture.summary(None)
        self.assertEqual(summary, summary_with_none)

    def test_summary_with_filtering_on_coap(self):

        # Get and check the summary
        summary = self.capture.summary(CoAP)
        self.assertTrue(type(summary), list)
        self.assertTrue(len(summary), 2)

        i = 4  # CoAP frames are n°4 and 5
        for f_sum in summary:
            self.check_summary(f_sum)
            self.assertEqual(f_sum[0], i)
            i += 1

    def test_summary_with_filtering_on_protocols(self):

        # For every implemented protocols
        for prots in get_dissectable_protocols():

            # Get and check the summary
            summary = self.capture.summary(prots)
            self.assertTrue(type(summary), list)
            for f_sum in summary:
                self.check_summary(f_sum)

    def test_summary_with_filtering_on_none_type(self):

        # Get and check the summary
        with self.assertRaises(InputParameterError):
            summary = self.capture.summary(type(None))

    def test_summary_with_filtering_on_not_a_protocol(self):

        # Get and check the summary
        with self.assertRaises(InputParameterError):
            summary = self.capture.summary(Frame)

    def test_summary_with_wrong_pcap_file(self):

        # Create two wrong dissect instances, assert an exeption is raised
        with self.assertRaises(ReaderError):
            dis_wrong_file = Capture(self.NOT_A_PCAP_FILE)
            dis = dis_wrong_file.summary()
        with self.assertRaises(ReaderError):
            dis_empty_file = Capture(self.EMPTY_PCAP_FILE)
            dis = dis_empty_file.summary()

    # ##### dissect
    def test_dissection_without_filtering(self):

        # Get and check the dissect
        dissect = self.capture.get_dissection()
        self.assertTrue(type(dissect), list)
        self.assertTrue(len(dissect), 5)

        i = 1
        for frame in dissect:
            self.struct_validator.check_frame(frame)
            self.assertEqual(frame['id'], i)
            i += 1

        # Try to get another dissect with None provided
        dissect_with_none = self.capture.get_dissection(None)
        self.assertEqual(dissect, dissect_with_none)

    def test_dissection_with_filtering_on_coap(self):

        # Get and check the dissect
        dissect = self.capture.get_dissection(CoAP)
        self.assertTrue(type(dissect), list)
        self.assertTrue(len(dissect), 2)

        i = 4  # CoAP frames are n°4 and 5
        for frame in dissect:
            self.struct_validator.check_frame(frame)
            self.assertEqual(frame['id'], i)
            i += 1

    def test_dissection_with_filtering_on_protocols(self):

        # For every implemented protocols
        for prots in get_dissectable_protocols():

            # Get and check the dissect
            dissect = self.capture.get_dissection(prots)
            self.assertTrue(type(dissect), list)
            for frame in dissect:
                self.struct_validator.check_frame(frame)

    def test_dissection_with_filtering_on_none_type(self):

        # Get and check the dissect
        with self.assertRaises(InputParameterError):
            dissect = self.capture.get_dissection(type(None))

    def test_dissection_with_filtering_on_not_a_protocol(self):

        # Get and check the dissect
        with self.assertRaises(InputParameterError):
            dissect = self.capture.get_dissection(Frame)

    def test_dissection_with_wrong_pcap_file(self):

        with self.assertRaises(ReaderError):
            dis_wrong_file = Capture(self.NOT_A_PCAP_FILE)
            dis = dis_wrong_file.get_dissection()
        with self.assertRaises(ReaderError):
            dis_empty_file = Capture(self.EMPTY_PCAP_FILE)
            dis = dis_empty_file.get_dissection()


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
