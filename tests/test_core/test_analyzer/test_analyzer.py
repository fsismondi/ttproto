import unittest

from ttproto.core.analyzer import Analyzer
from tests.test_tools.struct_checker import StructureChecker


class AnalyzerTestCase(unittest.TestCase):
    """
    Test class for the analyzer tool
    """

    # #################### Tests parameters #########################

    # Test env (only tat_coap for the moment)
    TEST_ENV = 'tat_coap'
    UNKNOWN_TEST_ENV = 'unknown'
    TEST_CASE_ID = 'TD_COAP_CORE_01'
    TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST = 'TD_COAP_CORE_24'
    UNKNOWN_TEST_CASE_ID = 'TD_COAP_CORE_42'

    # File path
    TEST_FILE_DIR = 'tests/test_dumps'
    PCAP_FILE = TEST_FILE_DIR + '/TD_COAP_CORE_01_PASS.pcap'
    WRONG_TEST_FILE_DIR = 'tests/test_files/WrongFilesForTests'
    EMPTY_PCAP_FILE = WRONG_TEST_FILE_DIR + '/empty_pcap.pcap'
    NOT_A_PCAP_FILE = WRONG_TEST_FILE_DIR + '/not_a_pcap_file.dia'

    # Create a struct checker object
    STRUCT_CHECKER = StructureChecker()

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the analyzer instance
        """
        self.analyzer = Analyzer(self.TEST_ENV)

    # ##### __init__
    def test___init__(self):

        # Initialize the analyzer with a correct test env
        analyzer = Analyzer(self.TEST_ENV)

    def test___init___unknown_test_env(self):

        # Initialize the analyzer with an unknown test env
        with self.assertRaises(NotADirectoryError):
            analyzer = Analyzer(self.UNKNOWN_TEST_ENV)

    # ##### get_implemented_testcases
    def test_get_implemented_testcases(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases()
        self.STRUCT_CHECKER.check_tc_from_analyzer(tcs)

    def test_get_implemented_testcases_with_none_value(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases(None)
        self.STRUCT_CHECKER.check_tc_from_analyzer(tcs)

    def test_get_implemented_testcases_single_test_case(self):

        # Get implemented test cases and check their values
        tc = self.analyzer.get_implemented_testcases(self.TEST_CASE_ID)
        self.STRUCT_CHECKER.check_tc_from_analyzer(tc)
        self.assertGreaterEqual(len(tc[0]), 0)
        self.assertGreaterEqual(len(tc[1]), 0)
        self.assertEqual(len(tc[0]) + len(tc[1]), 1)

    def test_get_implemented_testcases_verbose_mode(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases(verbose=True)
        self.STRUCT_CHECKER.check_tc_from_analyzer(tcs)

        # Check that they have the extra informations (the source code)
        for tc_type in tcs:
            for tc in tc_type:
                self.assertGreater(len(tc[2]), 0)

    def test_get_implemented_testcases_single_test_case_which_bugged(self):

        # Get implemented test cases and check their values
        tc = self.analyzer.get_implemented_testcases(
            self.TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST
        )
        self.STRUCT_CHECKER.check_tc_from_analyzer(tc)
        self.assertGreaterEqual(len(tc[0]), 0)
        self.assertGreaterEqual(len(tc[1]), 0)
        self.assertEqual(len(tc[0]) + len(tc[1]), 1)

    def test_get_implemented_testcases_unknown_test_case(self):

        # Get implemented test cases and check their values
        with self.assertRaises(FileNotFoundError):
            tc = self.analyzer.get_implemented_testcases(
                self.UNKNOWN_TEST_CASE_ID
            )


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
