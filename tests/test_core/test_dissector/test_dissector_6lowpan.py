import unittest
import os
import logging

from ttproto.core.dissector import Frame, Dissector, ReaderError
from ttproto.core.typecheck3000 import InputParameterError
from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.coap import CoAP
from ttproto.core.lib.inet.meta import InetPacketValue
from tests.test_tools.struct_validator import StructureValidator
from ttproto.utils.pcap_filter import openwsn_profile_filter

class DissectorTestCase(unittest.TestCase):
    """
    Test class for the dissector tool

    python3 -m unittest tests.test_core.test_dissector.test_dissector_6lowpan -vvv
    """

    # #################### Tests parameters #########################


    # File path
    TEST_FILE_DIR = 'tests/test_dumps/DissectorTests/6lowpan'
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

        for dirname, dirnames, filenames in os.walk('./' + self.TEST_FILE_DIR):
            for filename in filenames:
                #print("file: " + filename)
                complete_filename = os.path.join(dirname, filename)

                # case open wsn profile of pcap
                if "openwsn_captures" in dirname:
                    self.pcap_for_test.append(openwsn_profile_filter(complete_filename, self.TMP_DIR +
                                                                     "filtered_%s" %filename))
                # stack completelly dissectable by ttproto
                elif filename.endswith('.pcap'):
                    self.pcap_for_test.append(complete_filename)
                else:
                    logging.warning('[dissector unittests] file ignored for dissection: %s' %complete_filename)

        #print(self.pcap_to_be_preprocessed_first)
        #print(self.pcap_for_test)




        # 15.4 complete file
        #self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS = self.TEST_FILE_DIR + os.sep + "wpan_802_15_4_LLT_195_6lowpan.pcap"
        #self.pcap_for_test = []
        #self.pcap_for_test.append(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
        #self.filtered_pcap_filename = openwsn_profile_filter(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
        #self.dissector = Dissector(self.filtered_pcap_filename)

        # 15.4 ACKS
        #self.dissector = Dissector(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_ACKS)
        #self.filtered_pcap_filename = openwsn_profile_filter(self.PCAP_FILE_LINKTYPE_IEEE802_15_4_ACKS)
        #self.dissector = Dissector(self.filtered_pcap_filename)

        # CoAP
        # TEST_FILE_DIR = 'tests/test_dumps/DissectorTests'
        # PCAP_FILE = TEST_FILE_DIR + '/CoAP_plus_random_UDP_messages.pcap'
        # self.dissector = Dissector(PCAP_FILE)

        # 15.4 FCS

        #PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS= 'tests/test_dumps/6lowpan/802_15_4_with_FCS_13_frames.pcap'
        #self.dissector = Dissector(PCAP_FILE_LINKTYPE_IEEE802_15_4_FCS)
        #
        #self.dissector = Dissector(self.filtered_pcap_filename)

        #802_15_4_simple_FCS_test
        #pcap_name = "802_15_4_simple_FCS_test.pcap"
        #self.pcap_for_test=[]
        #file = os.path.join(self.TEST_FILE_DIR,"openwsn_captures",pcap_name)
        #self.filtered_pcap_filename = openwsn_profile_filter(file,'filtered_'+ pcap_name)
        #self.pcap_for_test.append(

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
        implemented_protocols = Dissector.get_implemented_protocols()
        print("implemented protos: " + str(implemented_protocols))
        self.assertEqual(type(implemented_protocols), list)
        self.assertGreater(len(implemented_protocols), 0)
        for prot in implemented_protocols:
            self.assertTrue(issubclass(prot, PacketValue))

    def test_dissect_pcaps_6lo(self):

        logging.info("[dissector unittests] loaded PCAPs to be dissected:")
        for p in self.pcap_for_test:
            logging.info(p)

        self.dissectors = []
        self.summaries = []
        for p_file in self.pcap_for_test:
            try:
                logging.debug('[dissector unittests] dissecting %s' %p_file )
                d = Dissector(p_file)
                self.dissectors.append(d)
            except:
                logging.error('[dissector unittests] exception trying to dissect %s' % p_file)
                raise
            finally:
                self.summaries.append(d.summary())


#     # ##### summary
#     def test_summary_without_filtering(self):
#
#         # Get and check the summary
#         summary = self.dissector.summary()
#         self.assertTrue(type(summary), list)
#         self.assertTrue(len(summary), 5)
#
#         i = 1
#         for f_sum in summary:
#             self.check_summary(f_sum)
#             self.assertEqual(f_sum[0], i)
#             i += 1
#
#         # Try to get another summary with None provided
#         summary_with_none = self.dissector.summary(None)
#         self.assertEqual(summary, summary_with_none)
#
#     def test_summary_with_filtering_on_coap(self):
#
#         # Get and check the summary
#         summary = self.dissector.summary(CoAP)
#         self.assertTrue(type(summary), list)
#         self.assertTrue(len(summary), 2)
#
#         i = 4  # CoAP frames are n°4 and 5
#         for f_sum in summary:
#             self.check_summary(f_sum)
#             self.assertEqual(f_sum[0], i)
#             i += 1
#
#     def test_summary_with_filtering_on_protocols(self):
#
#         # For every implemented protocols
#         for prots in Dissector.get_implemented_protocols():
#
#             # Get and check the summary
#             summary = self.dissector.summary(prots)
#             self.assertTrue(type(summary), list)
#             for f_sum in summary:
#                 self.check_summary(f_sum)
#
#     def test_summary_with_filtering_on_none_type(self):
#
#         # Get and check the summary
#         with self.assertRaises(InputParameterError):
#             summary = self.dissector.summary(type(None))
#
#     def test_summary_with_filtering_on_not_a_protocol(self):
#
#         # Get and check the summary
#         with self.assertRaises(InputParameterError):
#             summary = self.dissector.summary(Frame)
#
#     def test_summary_with_wrong_pcap_file(self):
#
#         # Create two wrong dissect instances
#         dis_wrong_file = Dissector(self.NOT_A_PCAP_FILE)
#         dis_empty_file = Dissector(self.EMPTY_PCAP_FILE)
#
#         # Get and check the summary
#         with self.assertRaises(ReaderError):
#             dis = dis_wrong_file.summary()
#         with self.assertRaises(ReaderError):
#             dis = dis_empty_file.summary()
#
#     # ##### dissect
#     def test_dissect_without_filtering(self):
#
#         # Get and check the dissect
#         dissect = self.dissector.dissect()
#         self.assertTrue(type(dissect), list)
#         self.assertTrue(len(dissect), 5)
#
#         i = 1
#         for frame in dissect:
#             self.struct_validator.check_frame(frame)
#             self.assertEqual(frame['id'], i)
#             i += 1
#
#         # Try to get another dissect with None provided
#         dissect_with_none = self.dissector.dissect(None)
#         self.assertEqual(dissect, dissect_with_none)
#
#     def test_dissect_with_filtering_on_coap(self):
#
#         # Get and check the dissect
#         dissect = self.dissector.dissect(CoAP)
#         self.assertTrue(type(dissect), list)
#         self.assertTrue(len(dissect), 2)
#
#         i = 4  # CoAP frames are n°4 and 5
#         for frame in dissect:
#             self.struct_validator.check_frame(frame)
#             self.assertEqual(frame['id'], i)
#             i += 1
#
#     def test_dissect_with_filtering_on_protocols(self):
#
#         # For every implemented protocols
#         for prots in Dissector.get_implemented_protocols():
#             print("protooo:  ->" +str(prots))
#
#             # Get and check the dissect
#             dissect = self.dissector.dissect(prots)
#             self.assertTrue(type(dissect), list)
#             for frame in dissect:
#                 self.struct_validator.check_frame(frame)
#
#     def test_dissect_with_filtering_on_none_type(self):
#
#         # Get and check the dissect
#         with self.assertRaises(InputParameterError):
#             dissect = self.dissector.dissect(type(None))
#
#     def test_dissect_with_filtering_on_not_a_protocol(self):
#
#         # Get and check the dissect
#         with self.assertRaises(InputParameterError):
#             dissect = self.dissector.dissect(Frame)
#
#     def test_dissect_with_wrong_pcap_file(self):
#
#         # Create two wrong dissect instances
#         dis_wrong_file = Dissector(self.NOT_A_PCAP_FILE)
#         dis_empty_file = Dissector(self.EMPTY_PCAP_FILE)
#
#         # Get and check the dissect
#         with self.assertRaises(ReaderError):
#             dis = dis_wrong_file.dissect()
#         with self.assertRaises(ReaderError):
#             dis = dis_empty_file.dissect()
#
# # #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main(verbosity=3)
