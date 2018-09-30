from ttproto.core.analyzer import Analyzer
from ttproto.core.templates import Length, Regex, All, Range, Any, AnyValue
import unittest
import os
import logging

logging.basicConfig()
logger = logging.getLogger(__name__)
# Change logging level here.
logger.setLevel(os.environ.get('LOG_LEVEL', logging.INFO))
default_expected_verdict_if_none_specified = "pass"


class TestAnalysisInteropTestCase(unittest.TestCase):

    def setUp(self):
        self.pcap_dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../test_dumps')
        self.pcap_path_list = os.listdir(self.pcap_dir_path)
        logger.info(self.pcap_path_list)

    def get_pcaps(self):
        for entry in self.pcap_path_list:
            full_path = os.path.join(self.pcap_dir_path, entry)
            if os.path.isfile(full_path) and full_path.endswith('.pcap'):
                yield full_path

    def __get_test_case_from_full_path(self, pcap_path):
        if 'PASS' in pcap_path:
            return pcap_path[pcap_path.find('TD'):(pcap_path.find('PASS') - 1)]
        elif 'FAIL' in pcap_path:
            return pcap_path[pcap_path.find('TD'):(pcap_path.find('FAIL') - 1)]
        elif 'INCONCLUSIVE' in pcap_path:
            return pcap_path[pcap_path.find('TD'):(pcap_path.find('INCONCLUSIVE') - 1)]
        else:
            return None

    def test_td_coap(self):
        for pcap_name in self.get_pcaps():
            expected_verdict = None
            if 'PASS' in pcap_name:
                expected_verdict = 'pass'
            elif 'FAIL' in pcap_name:
                expected_verdict = 'fail'
            elif 'INCONCLUSIVE' in pcap_name:
                expected_verdict = 'inconclusive'
            else:
                if default_expected_verdict_if_none_specified == "error":
                    raise Exception("No verdict in name with pcap filename " + pcap_name)
                else:
                    expected_verdict = default_expected_verdict_if_none_specified
            analyzer = Analyzer('tat_coap')

            test_case = self.__get_test_case_from_full_path(pcap_name)
            if test_case is None:
                logging.info("Ignored file " + pcap_name + " because we couldn't determine the relevant test case.")
                continue

            logging.info("Testing " + test_case + "\n With file " + pcap_name)

            tc_name, verdict, rev_frames, log, partial_verdicts, exception_info = analyzer.analyse(pcap_name, test_case)
            assert verdict == expected_verdict, log

            logging.info(test_case + " PASSED.")
