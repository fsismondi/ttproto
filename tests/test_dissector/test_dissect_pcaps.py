import os
import json
import logging
import unittest

from tests.test_tools.struct_validator import StructureValidator

from ttproto import TMPDIR
from ttproto.core.packet import PacketValue
from ttproto.core.lib.inet.coap import CoAP
from ttproto.core.dissector import Capture, get_dissectable_protocols
from ttproto.utils.pcap_filter import openwsn_profile_filter


class DissectPcapTestCase(unittest.TestCase):
    """
    Test pcap dissections using as input pcap files.

    This class can be inherited, and child class may have
    PCAP_FILES_DISSECTION_DIRS and PROTO_CLASS_FILTER
    overriden for running test over particular protocols.
    """

    # #################### Tests parameters #########################

    # File path
    PCAP_FILES_DISSECTION_DIRS = [
        'tests/test_dumps/lwm2m_pro',
    ]

    PROTO_CLASS_FILTER = CoAP  # we can override with None :)

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
                        self.pcap_for_test.append(
                            openwsn_profile_filter(complete_filename, os.path.join(TMPDIR, "filtered_%s" % filename))
                        )
                    # stack completely dissectable by ttproto
                    elif filename.endswith('.pcap'):
                        self.pcap_for_test.append(complete_filename)
                    else:
                        logging.warning('[dissector unittests] file ignored for dissection: %s' % complete_filename)

    def test_get_implemented_protocols(self):
        # Get implemented protocols and check their values
        implemented_protocols = get_dissectable_protocols()
        logging.info("implemented protos: " + str(implemented_protocols))
        self.assertEqual(type(implemented_protocols), list)
        self.assertGreater(len(implemented_protocols), 0)
        for prot in implemented_protocols:
            self.assertTrue(issubclass(prot, PacketValue))

    def test_that_it_can_dissect_all_pcaps(self):
        """
        this basicallyt test that the decoders dont raise any errors
        :return:
        """

        logging.info(
            "[dissector unittests] loaded %s .pcap files for dissection tests" % len(self.pcap_for_test))

        for p_file in self.pcap_for_test:
            logging.info('[dissector unittests] dissecting %s' % p_file)
            c = Capture(p_file)
            d = c.get_dissection()
            try:
                logging.debug('frame dissection: %s' % json.dumps(d, indent=4))
            except:
                logging.debug('frame dissection: %s' % d)

    def test_dissected_pcaps_returned_values_are_not_empty(self):
        """
        this test that the decoders dont raise any errors
        :return:
        """

        logging.info(
            "[dissector unittests] loaded %s .pcap files for dissection tests" % len(self.pcap_for_test))

        for p_file in self.pcap_for_test:
            logging.info('[dissector unittests] dissecting %s' % p_file)
            c = Capture(p_file)
            d = c.get_dissection(self.PROTO_CLASS_FILTER)
            if len(d) == 0:
                self.fail('got empty dissection for %s layer for .pcap %s' % (self.PROTO_CLASS_FILTER, p_file))
            logging.debug('frame dissection: %s' % json.dumps(d, indent=4))


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
