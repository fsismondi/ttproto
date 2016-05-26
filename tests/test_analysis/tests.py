import unittest
from ttproto.ts_coap.analysis import basic_dissect_pcap_to_json, dissect_pcap_to_json
from ttproto.core.lib.inet.coap import *
from os import getcwd
import json


class AnalysisTestCase(unittest.TestCase):
    PCAP_test = getcwd() + '/tests/test_dumps/obs_large.pcap'

    def test_basic_dissect_pcap_json_return_two_elements_coap(self):
        a = basic_dissect_pcap_to_json(self.PCAP_test, True)
        #print(a)
        self.assertEqual(len(json.loads(a)), 16)

    def test_basic_dissect_pcap_json_return_all_frames(self):
        a = basic_dissect_pcap_to_json(self.PCAP_test, False)
        #print(a)
        self.assertEqual(len(json.loads(a)), 16)

    # TODO add tests with PCAPs that are not only coap based, check protocol return_only_coap feature works properly

    def test_dissect_pcap_json_return_all_frames(self):
        a = dissect_pcap_to_json(self.PCAP_test, CoAP)
        #print(a)
        self.assertEqual(len(json.loads(a)), 16)


if __name__ == '__main__':
    unittest.main()
