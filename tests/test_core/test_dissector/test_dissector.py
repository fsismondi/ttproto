import unittest

from ttproto.core.dissector import Frame, Dissector, ReaderError
from ttproto.core.typecheck3000 import InputParameterError
from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.coap import CoAP
from ttproto.core.lib.inet.meta import InetPacketValue
from tests.test_tools.struct_validator import StructureValidator


class DissectorTestCase(unittest.TestCase):
    """
    Test class for the dissector tool
    """

    # #################### Tests parameters #########################

    # File path
    TEST_FILE_DIR = 'tests/test_dumps/dissection'

    # dissect CoAP pcap with other UDP messages:
    PCAP_FILE = TEST_FILE_DIR + '/coap/CoAP_plus_random_UDP_messages.pcap'

    # pcaps that MUST throw exceptions
    WRONG_TEST_FILE_DIR = TEST_FILE_DIR + '/exceptions'
    EMPTY_PCAP_FILE = WRONG_TEST_FILE_DIR + '/empty_pcap.pcap'
    NOT_A_PCAP_FILE = WRONG_TEST_FILE_DIR + '/not_a_pcap_file.dia'

    # Create a struct checker object
    struct_validator = StructureValidator()

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the dissector instance
        """
        self.dissector = Dissector(self.PCAP_FILE)


    # #################### Utilities functions #########################

    def check_summary(self, summary):
        self.assertTrue(type(summary), tuple)
        self.assertEqual(len(summary), 2)
        self.assertTrue(type(summary[0]), int)
        self.assertGreater(summary[0], 0)
        self.assertTrue(type(summary[1]), str)
        self.assertGreater(len(summary[1]), 0)

    # #################### Tests functions #########################

    # ##### get_implemented_protocols
    def test_get_implemented_protocols(self):

        # Get implemented protocols and check their values
        implemented_protocols = Dissector.get_implemented_protocols()
        self.assertEqual(type(implemented_protocols), list)
        self.assertGreater(len(implemented_protocols), 0)
        for prot in implemented_protocols:
            self.assertTrue(issubclass(prot, PacketValue))

    # ##### summary
    def test_summary_without_filtering(self):

        # Get and check the summary
        summary = self.dissector.summary()
        self.assertTrue(type(summary), list)
        self.assertTrue(len(summary), 5)

        i = 1
        for f_sum in summary:
            self.check_summary(f_sum)
            self.assertEqual(f_sum[0], i)
            i += 1

        # Try to get another summary with None provided
        summary_with_none = self.dissector.summary(None)
        self.assertEqual(summary, summary_with_none)

    def test_summary_with_filtering_on_coap(self):

        # Get and check the summary
        summary = self.dissector.summary(CoAP)
        self.assertTrue(type(summary), list)
        self.assertTrue(len(summary), 2)

        i = 4  # CoAP frames are n°4 and 5
        for f_sum in summary:
            self.check_summary(f_sum)
            self.assertEqual(f_sum[0], i)
            i += 1

    def test_summary_with_filtering_on_protocols(self):

        # For every implemented protocols
        for prots in Dissector.get_implemented_protocols():

            # Get and check the summary
            summary = self.dissector.summary(prots)
            self.assertTrue(type(summary), list)
            for f_sum in summary:
                self.check_summary(f_sum)

    def test_summary_with_filtering_on_none_type(self):

        # Get and check the summary
        with self.assertRaises(InputParameterError):
            summary = self.dissector.summary(type(None))

    def test_summary_with_filtering_on_not_a_protocol(self):

        # Get and check the summary
        with self.assertRaises(InputParameterError):
            summary = self.dissector.summary(Frame)

    def test_summary_with_wrong_pcap_file(self):

        # Create two wrong dissect instances
        dis_wrong_file = Dissector(self.NOT_A_PCAP_FILE)
        dis_empty_file = Dissector(self.EMPTY_PCAP_FILE)

        # Get and check the summary
        with self.assertRaises(ReaderError):
            dis = dis_wrong_file.summary()
        with self.assertRaises(ReaderError):
            dis = dis_empty_file.summary()

    # ##### dissect
    def test_dissect_without_filtering(self):

        # Get and check the dissect
        dissect = self.dissector.dissect()
        self.assertTrue(type(dissect), list)
        self.assertTrue(len(dissect), 5)

        i = 1
        for frame in dissect:
            self.struct_validator.check_frame(frame)
            self.assertEqual(frame['id'], i)
            i += 1

        # Try to get another dissect with None provided
        dissect_with_none = self.dissector.dissect(None)
        self.assertEqual(dissect, dissect_with_none)

    def test_dissect_with_filtering_on_coap(self):

        # Get and check the dissect
        dissect = self.dissector.dissect(CoAP)
        self.assertTrue(type(dissect), list)
        self.assertTrue(len(dissect), 2)

        i = 4  # CoAP frames are n°4 and 5
        for frame in dissect:
            self.struct_validator.check_frame(frame)
            self.assertEqual(frame['id'], i)
            i += 1

    def test_dissect_with_filtering_on_protocols(self):

        # For every implemented protocols
        for prots in Dissector.get_implemented_protocols():

            # Get and check the dissect
            dissect = self.dissector.dissect(prots)
            self.assertTrue(type(dissect), list)
            for frame in dissect:
                self.struct_validator.check_frame(frame)

    def test_dissect_with_filtering_on_none_type(self):

        # Get and check the dissect
        with self.assertRaises(InputParameterError):
            dissect = self.dissector.dissect(type(None))

    def test_dissect_with_filtering_on_not_a_protocol(self):

        # Get and check the dissect
        with self.assertRaises(InputParameterError):
            dissect = self.dissector.dissect(Frame)

    def test_dissect_with_wrong_pcap_file(self):

        # Create two wrong dissect instances
        dis_wrong_file = Dissector(self.NOT_A_PCAP_FILE)
        dis_empty_file = Dissector(self.EMPTY_PCAP_FILE)

        # Get and check the dissect
        with self.assertRaises(ReaderError):
            dis = dis_wrong_file.dissect()
        with self.assertRaises(ReaderError):
            dis = dis_empty_file.dissect()

# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
