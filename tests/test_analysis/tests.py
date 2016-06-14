#!/usr/bin/env python3
import unittest
from ttproto.ts_coap.analysis import basic_dissect_pcap_to_list, dissect_pcap_to_list
from ttproto.core.lib.inet.coap import *
from os import getcwd
import json


class AnalysisTestCase(unittest.TestCase):
    PCAP_test = getcwd() + '/tests/test_dumps/coap_get_migled_with_tcp_traffic.pcap'

    def test_basic_dissect_pcap_list_return_four_elements_coap(self):
        a = basic_dissect_pcap_to_list(self.PCAP_test, CoAP)
        #print(a)
        self.assertEqual(len(a), 4)

    def test_basic_dissect_pcap_list_return_all_frames(self):
        a = basic_dissect_pcap_to_list(self.PCAP_test, None)
        #print(a)
        self.assertEqual(len(a), 28)

    # TODO add tests with PCAPs that are not only coap based, check protocol return_only_coap feature works properly


    def test_dissect_pcap_list_return_coap_frames(self):
        a = dissect_pcap_to_list(self.PCAP_test, CoAP)
        #print(a)
        self.assertEqual(len(a), 4)

    def test_dissect_pcap_list_return_all_frames(self):
        a = dissect_pcap_to_list(self.PCAP_test, None)
        #print(a)
        self.assertEqual(len(a), 28)


if __name__ == '__main__':
    unittest.main()
