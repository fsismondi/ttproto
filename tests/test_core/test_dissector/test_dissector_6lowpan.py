import unittest
import os
import logging

from ttproto.core.dissector import Frame, Capture, ReaderError
from ttproto.core.packet import PacketValue
from tests.test_tools.struct_validator import StructureValidator
from ttproto.utils.pcap_filter import openwsn_profile_filter


class DissectorTestCase(unittest.TestCase):
    """
    Test class for the dissector tool

    python3 -m unittest tests.test_core.test_dissector.test_dissector_6lowpan -vvv
    """

    # #################### Tests parameters #########################

    # File path
    PCAP_FILES_DISSECTION_DIRS = ['tests/test_dumps/dissection/6lowpan',
                                  'tests/test_dumps/analysis/6lowpan_hc',
                                  'tests/test_dumps/analysis/6lowpan_nd']
    TMP_DIR = 'tmp/'

    # Create a struct checker object
    struct_validator = StructureValidator()

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the dissector instance
        """

        self.pcap_for_test = []
        self.pcap_to_be_preprocessed_first = []

        for pcap_dir in self.PCAP_FILES_DISSECTION_DIRS:
            for dirname, dirnames, filenames in os.walk('./' + pcap_dir):
                for filename in filenames:
                    # print("file: " + filename)
                    complete_filename = os.path.join(dirname, filename)

                    # case open wsn profile of pcap
                    if "openwsn_captures" in dirname:
                        self.pcap_for_test.append(openwsn_profile_filter(complete_filename, self.TMP_DIR +
                                                                         "filtered_%s" % filename))
                    # stack completely dissectable by ttproto
                    elif filename.endswith('.pcap'):
                        self.pcap_for_test.append(complete_filename)
                    else:
                        logging.warning('[dissector unittests] file ignored for dissection: %s' % complete_filename)

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

    def test_get_implemented_protocols(self):

        # Get implemented protocols and check their values
        implemented_protocols = Capture.get_implemented_protocols()
        print("implemented protos: " + str(implemented_protocols))
        self.assertEqual(type(implemented_protocols), list)
        self.assertGreater(len(implemented_protocols), 0)
        for prot in implemented_protocols:
            self.assertTrue(issubclass(prot, PacketValue))

    def test_dissect_pcaps_6lo(self):

        logging.info("[dissector unittests] loaded %s .pcap files for dissection tests" % len(self.pcap_for_test))
        # for p in self.pcap_for_test:
        #     logging.info(p)

        self.dissected_pcaps = []
        self.summaries = []
        for p_file in self.pcap_for_test:
            logging.info('[dissector unittests] dissecting %s' % p_file)
            d = Capture(p_file).dissect()
            self.dissected_pcaps.append(d)
            self.summaries.append(d.summary())
            assert d, 'Empty result/dissection for .pcap : %s'% p_file


# # #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main(verbosity=3)
