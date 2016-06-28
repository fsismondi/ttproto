import unittest

from ttproto.core.dissector import Frame, Dissector
from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.coap import CoAP
from ttproto.core.lib.inet.meta import InetPacketValue


class DissectorTestCase(unittest.TestCase):
    """
    Test class for the dissector tool
    """

    # #################### Tests parameters #########################

    # File path
    TEST_FILE_DIR = 'tests/test_files/DissectorTests'
    PCAP_FILE = TEST_FILE_DIR + '/CoAP_plus_random_UDP_messages.pcap'
    WRONG_TEST_FILE_DIR = 'tests/test_files/WrongFilesForTests'
    EMPTY_PCAP_FILE = WRONG_TEST_FILE_DIR + '/empty_pcap.pcap'
    NOT_A_PCAP_FILE = WRONG_TEST_FILE_DIR + '/not_a_pcap_file.dia'

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

        # Check that the InetPacketValue isn't there
        self.assertNotIn(InetPacketValue, implemented_protocols)

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
        with self.assertRaises(TypeError):
            summary = self.dissector.summary(type(None))

    def test_summary_with_filtering_on_not_a_protocol(self):

        # Get and check the summary
        with self.assertRaises(TypeError):
            summary = self.dissector.summary(Frame)

# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
