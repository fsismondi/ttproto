#!/usr/bin/env python3
import unittest
from ttproto.ts_coap.analysis import basic_dissect_pcap_to_list, dissect_pcap_to_list, analyse_file_rest_api, get_implemented_testcases
from ttproto.core.lib.inet.coap import *
from os import getcwd, path
import json

DUMPS_DIR = '/tests/test_dumps'

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

    def one_pcap_pass_test_per_testcase(self):
        list_TC =  b = [(tc_i[0]) for tc_i in get_implemented_testcases(no_verbose=True)]
        print(list_TC)
        print(getcwd())
        for tc in list_TC:
            pcap_filename = getcwd() +"/"+ DUMPS_DIR +"/"+ str(tc) + "_PASS.pcap"
            print(pcap_filename + " || "+ str(path.isfile(pcap_filename)))
            self.assertTrue(path.isfile(pcap_filename))


    # TODO add FAIL, and PASS test for each implemented TC
    def test_analysis_api_pass_basic_pass_PCAPs(self):
        """
        ATTENTION conventions used here:
        every pcap_pass_test needs to follow the convention of <TC name>_<verdict>_<optional : reason why testing tool should provide the mentioned verdict>_<option: number>.pcap
        :return:
        """
        list_TC =  b = [(tc_i[0]) for tc_i in get_implemented_testcases(no_verbose=True)]
        for tc in list_TC:
            pcap_filename = getcwd() + "/" + DUMPS_DIR + "/" + str(tc) + "_PASS.pcap"
            # check if there's a pcap_pass_test for the testcase
            if path.isfile(pcap_filename):
                print("verifying test case: " + tc)
                pcap_filename = getcwd() + "/" + DUMPS_DIR + "/" + str(tc) + "_PASS.pcap"
                #verdict,_,_ = analyse_file_rest_api(pcap_filename, False, None, tc, "client", False)
                tc_name, verdict, _, log = analyse_file_rest_api(pcap_filename, False, None, tc, "client", True)[0]
                self.assertTrue(verdict=='pass',msg='TC implementation not passing the pcap_pass_test' + '\n' + 'VERDICT: '+ verdict + '\nLOG:\n' + log)



if __name__ == '__main__':
    unittest.main()
