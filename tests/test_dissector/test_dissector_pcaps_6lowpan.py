import unittest
import os
import json
import logging

from ttproto.core.dissector import Capture, get_dissectable_protocols
from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.sixlowpan import SixLowpan
from ttproto.utils.pcap_filter import openwsn_profile_filter

from tests.test_tools.struct_validator import StructureValidator
from tests.test_dissector.test_dissect_pcaps import DissectPcapTestCase


class DissectorTestCase_6lowpan(DissectPcapTestCase):
    """
    Test class for the dissector tool

    python3 -m unittest tests.test_dissector.test_dissector_6lowpan.DissectorTestCase.test_that_it_can_dissect_all_pcaps -vvv
    """

    # #################### Tests parameters #########################

    # File path
    PCAP_FILES_DISSECTION_DIRS = ['tests/test_dumps/6lowpan',
                                  'tests/test_dumps/6lowpan_hc',
                                  'tests/test_dumps/6lowpan_nd']
    PROTO_CLASS_FILTER = SixLowpan
    TMP_DIR = 'tmp/'

    # Create a struct checker object
    struct_validator = StructureValidator()



# # #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main(verbosity=3)

    # 15.4 complete file
    # self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS = self.PCAP_FILES_DISSECTION + os.sep + "wpan_802_15_4_LLT_195_6lowpan.pcap"
    # self.pcap_for_test = []
    # self.pcap_for_test.append(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
    # self.filtered_pcap_filename = openwsn_profile_filter(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
    # self.dissector = Dissector(self.filtered_pcap_filename)

    # 15.4 ACKS
    # self.dissector = Dissector(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_ACKS)
    # self.filtered_pcap_filename = openwsn_profile_filter(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_ACKS)
    # self.dissector = Dissector(self.filtered_pcap_filename)

    # CoAP
    # PCAP_FILES_DISSECTION = 'tests/test_dumps/dissection'
    # PCAP_FILE = PCAP_FILES_DISSECTION + '/CoAP_plus_random_UDP_messages.pcap'
    # self.dissector = Dissector(PCAP_FILE)

    # 15.4 FCS

    # PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS= 'tests/test_dumps/6lowpan/802_15_4_with_FCS_13_frames.pcap'
    # self.dissector = Dissector(PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
    #
    # self.dissector = Dissector(self.filtered_pcap_filename)

    # 802_15_4_simple_FCS_test
    # pcap_name = "802_15_4_simple_FCS_test.pcap"
    # self.pcap_for_test=[]
    # file = os.path.join(self.PCAP_FILES_DISSECTION,"openwsn_captures",pcap_name)
    # self.filtered_pcap_filename = openwsn_profile_filter(file,'filtered_'+ pcap_name)
    # self.pcap_for_test.append(

    # #################### Utilities functions #########################
    #
    # def test_check_summary(self, summary):
    #     self.assertTrue(type(summary), tuple)
    #     self.assertEqual(len(summary), 2)
    #     self.assertTrue(type(summary[0]), int)
    #     self.assertGreater(summary[0], 0)
    #     self.assertTrue(type(summary[1]), str)
    #     self.assertGreater(len(summary[1]), 0)

    # #################### Tests functions #########################

    # ##### get_implemented_protocols
