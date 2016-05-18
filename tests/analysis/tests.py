import unittest
from ttproto.ts_coap.analysis import dissect_frames_json
from os import getcwd
import json


class AnalysisTests(unittest.TestCase):

    def test_dissect_frames_json_return_two_elements_coap(self):
        a = dissect_frames_json( getcwd() + '/tests/test_dumps/two_coap_frames_get_NON.pcap',True)
        self.assertEqual(len(json.loads(a)),2)

    def test_dissect_frames_json_return_all_frames(self):
        a = dissect_frames_json(getcwd() + '/tests/test_dumps/two_coap_frames_get_NON.pcap', False)
        self.assertEqual(len(json.loads(a)), 314)

if __name__ == '__main__':
    unittest.main()