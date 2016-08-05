import unittest

from ttproto.core.analyzer import Filter, TestCase
from ttproto.core.dissector import Capture, Frame
from ttproto.core.typecheck3000 import InputParameterError
from ttproto.core.lib.all import *
from ttproto.tat_coap.testcases.td_coap_core_02 import TD_COAP_CORE_02
from ttproto.tat_coap.testcases.td_coap_core_03 import TD_COAP_CORE_03
from ttproto.tat_coap.testcases.td_coap_core_04 import TD_COAP_CORE_04
from ttproto.tat_coap.testcases.td_coap_core_07 import TD_COAP_CORE_07
from ttproto.tat_coap.testcases.td_coap_core_20 import TD_COAP_CORE_20


class FilterTestCase(unittest.TestCase):
    """
    Test class for the Filter class
    """
    # #################### Tests parameters #########################

    # The files used here
    TEST_FILE_DIR = 'tests/test_dumps/coap'
    CORE_02 = TEST_FILE_DIR + '/TD_COAP_CORE_02_PASS.pcap'
    CORE_02_MULTIPLE = TEST_FILE_DIR + '/TD_COAP_CORE_02_MULTIPLETIMES.pcap'
    NESTED_CONV = TEST_FILE_DIR + '/03_20_04_20_07.pcap'
    CONV_WITH_NOISE = TEST_FILE_DIR + '/TD_COAP_CORE_07_FAIL_No_CoAPOptionContentFormat_plus_random_UDP_messages.pcap'

    # The nested conv configuration:
    #   - Class of TestCasse
    #   - Number of occurences
    #   - Number of frame per conversation
    #   - Number of ignored frames
    #
    # The number of frame per conv is not really what it is because we take the
    # frames following the stimulus without stopping after what we need.
    NESTED_CONFIG = [
        (TD_COAP_CORE_03, 1, 14, 0),
        (TD_COAP_CORE_20, 2, 6, 2),
        (TD_COAP_CORE_04, 1, 8, 6),
        (TD_COAP_CORE_07, 1, 2, 12)
    ]

    # Wrong implementation of test case class
    class TestCaseClassEmptyList(TestCase):

        @classmethod
        def get_stimulis(cls):
            """
            Wrong implementation of get_stimulis()
            """
            return []

        @classmethod
        def get_nodes(cls):
            """
            Wrong implementation of get_stimulis()
            """
            return []

        @classmethod
        def get_protocol(cls):
            """
            Wrong implementation of get_protocol()
            """
            return [CoAP]

    class TestCaseClassNone(TestCase):

        @classmethod
        def get_stimulis(cls):
            """
            Wrong implementation of get_stimulis()
            """
            return None

        @classmethod
        def get_nodes(cls):
            """
            Wrong implementation of get_stimulis()
            """
            return None

        @classmethod
        def get_protocol(cls):
            """
            Wrong implementation of get_protocol()
            """
            return None

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the filter instance
        """
        self.tc_filter = Filter(Capture(self.CORE_02), TD_COAP_CORE_02)

    # #################### Tests functions #########################

    # ##### __init__
    def test___init__string_values(self):

        # String instead of capture
        with self.assertRaises(InputParameterError):
            self.tc_filter = Filter(self.CORE_02, TD_COAP_CORE_02)

        # String instead of tc class
        with self.assertRaises(InputParameterError):
            self.tc_filter = Filter(Capture(self.CORE_02), self.CORE_02)

    def test___init__wrong_test_case_class(self):

        # String instead of capture
        with self.assertRaises(ValueError):
            self.tc_filter = Filter(Capture(self.CORE_02), self.TestCaseClassEmptyList)

        # String instead of tc class
        with self.assertRaises(ValueError):
            self.tc_filter = Filter(Capture(self.CORE_02), self.TestCaseClassNone)

    # ##### conversations
    def test_conversations_normal(self):

        # Check normal conversation of TD_COAP_CORE_02
        conversations = self.tc_filter.conversations
        self.assertIsInstance(conversations, list)
        self.assertEqual(len(conversations), 1)

        # Check the number of frames into the single conv
        self.assertEqual(len(conversations[0]), 2)
        for frame in conversations[0]:
            self.assertIsInstance(frame, Frame)

        # Check that setting conversations is blocked
        with self.assertRaises(AttributeError):
            self.tc_filter.conversations = conversations

    def test_conversations_multiple_instance(self):

        self.tc_filter = Filter(
            Capture(self.CORE_02_MULTIPLE),
            TD_COAP_CORE_02
        )

        # Check normal conversation of TD_COAP_CORE_02
        conversations = self.tc_filter.conversations
        self.assertIsInstance(conversations, list)
        self.assertEqual(len(conversations), 10)

        # Check the number of frames into each conv
        for conv in conversations:
            self.assertEqual(len(conv), 2)
            for frame in conv:
                self.assertIsInstance(frame, Frame)

        # Check that setting conversations is blocked
        with self.assertRaises(AttributeError):
            self.tc_filter.conversations = conversations

    def test_conversations_nested(self):

        # For each nested tc occurences in the config
        for tc, nb_conv, nb_frame, nb_ignored in self.NESTED_CONFIG:

            self.tc_filter = Filter(
                Capture(self.NESTED_CONV),
                tc
            )

            # Check normal conversation of TD_COAP_CORE_02
            conversations = self.tc_filter.conversations
            self.assertIsInstance(conversations, list)
            self.assertEqual(len(conversations), nb_conv)

            # Check the number of frames into each conv
            for conv in conversations:
                self.assertEqual(len(conv), nb_frame)
                for frame in conv:
                    self.assertIsInstance(frame, Frame)

        # Check that setting conversations is blocked
        with self.assertRaises(AttributeError):
            self.tc_filter.conversations = conversations

    # ##### ignored
    def test_ignored_normal(self):

        # Check normal conversation of TD_COAP_CORE_02
        ignored = self.tc_filter.ignored
        self.assertIsInstance(ignored, list)
        self.assertEqual(len(ignored), 0)

    def test_ignored_multiple_instance(self):

        self.tc_filter = Filter(
            Capture(self.CORE_02_MULTIPLE),
            TD_COAP_CORE_02
        )

        # Check normal conversation of TD_COAP_CORE_02
        ignored = self.tc_filter.ignored
        self.assertIsInstance(ignored, list)
        self.assertEqual(len(ignored), 0)

    def test_ignored_nested(self):

        # For each nested tc occurences in the config
        for tc, nb_conv, nb_frame, nb_ignored in self.NESTED_CONFIG:

            self.tc_filter = Filter(
                Capture(self.NESTED_CONV),
                tc
            )

            # Check normal conversation of TD_COAP_CORE_02
            ignored = self.tc_filter.ignored
            self.assertIsInstance(ignored, list)
            self.assertEqual(len(ignored), nb_ignored)

    def test_ignored_correct_tc_with_udp_noises(self):

        self.tc_filter = Filter(Capture(self.CONV_WITH_NOISE), TD_COAP_CORE_07)

        conversations = self.tc_filter.conversations
        ignored = self.tc_filter.ignored

        # The PCAP file of this test doesn't contain any TC occurence because
        # the stimuli doesn't exist

        self.assertIsInstance(conversations, list)
        self.assertIsInstance(ignored, list)
        self.assertEqual(len(conversations), 0)
        self.assertEqual(len(ignored), 5)

        # Check the frames
        for frame in ignored:
            self.assertIsInstance(frame, Frame)


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
