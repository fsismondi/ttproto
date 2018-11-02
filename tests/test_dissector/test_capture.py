import unittest
from os import path

from ttproto.core.dissector import Frame, Capture, ReaderError


class CaptureTestCase(unittest.TestCase):
    """
    Test class for the capture tool
    """

    # #################### Tests parameters #########################

    # File path
    TEST_FILE_DIR = 'tests/test_dumps'
    PCAP_FILE = path.join(TEST_FILE_DIR, 'coap', 'CoAP_plus_random_UDP_messages.pcap')

    # pcaps that MUST throw exceptions
    WRONG_TEST_FILE_DIR_NAME = 'others'
    EMPTY_PCAP_FILE = path.join(TEST_FILE_DIR, WRONG_TEST_FILE_DIR_NAME, 'empty_pcap.pcap')
    NOT_A_PCAP_FILE = path.join(TEST_FILE_DIR, WRONG_TEST_FILE_DIR_NAME, 'not_a_pcap_file.dia')

    CAPTURE_LENGTH = 5

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the Capture instance
        """
        self.capture = Capture(self.PCAP_FILE)

    # #################### Tests functions #########################

    # ##### filename
    def test_get_filename(self):
        self.assertEqual(self.capture.filename, self.PCAP_FILE)

    def test_set_filename(self):
        with self.assertRaises(AttributeError):
            self.capture.filename = 'New filename'

    # ##### frames
    def test_get_frames(self):
        self.assertEqual(
            len(self.capture.frames) + len(self.capture.malformed),
            self.CAPTURE_LENGTH
        )
        for frame in self.capture.frames:
            self.assertIsInstance(frame, Frame)

    def test_set_frames(self):
        with self.assertRaises(AttributeError):
            self.capture.frames = []

    # ##### frames
    def test_get_malformed(self):
        self.assertEqual(
            len(self.capture.malformed) + len(self.capture.frames),
            self.CAPTURE_LENGTH
        )
        for malformed_frame in self.capture.malformed:
            self.assertIsInstance(malformed_frame, Frame)
            self.assertIsNotNone(malformed_frame['error'])

    def test_set_malformed(self):
        with self.assertRaises(AttributeError):
            self.capture.malformed = []


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
