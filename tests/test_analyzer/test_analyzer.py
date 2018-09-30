import unittest, logging, json

from os import getcwd, path
from ttproto.core.analyzer import Analyzer
from ttproto.core.typecheck3000 import InputParameterError
from tests.test_tools.struct_validator import StructureValidator


class CoAPAnalyzerTestCase(unittest.TestCase):
    """
    Test class for the analyzer tool
    """

    # #################### Tests parameters #########################

    # Test env (only tat_coap for the moment)
    TEST_ENV = 'tat_coap'
    TEST_DIR = './tests/test_dumps/coap_core/'
    UNKNOWN_TEST_ENV = 'unknown'
    TEST_CASE_ID = 'TD_COAP_CORE_01'
    TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST = 'TD_COAP_CORE_24'
    UNKNOWN_TEST_CASE_ID = 'TD_COAP_CORE_42'

    # Create a struct checker object
    struct_validator = StructureValidator()

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the analyzer instance
        """
        self.analyzer = Analyzer(self.TEST_ENV)

    # #################### Tests functions #########################

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
        self.struct_validator.check_tc_from_analyzer(tcs)

    def test_get_implemented_testcases_with_none_value(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases(None)
        self.struct_validator.check_tc_from_analyzer(tcs)

    def test_get_implemented_testcases_single_test_case(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases([self.TEST_CASE_ID])
        self.struct_validator.check_tc_from_analyzer(tcs)
        self.assertEqual(len(tcs), 1)
        self.assertEqual(tcs[0][0], self.TEST_CASE_ID)

    def test_get_implemented_testcases_verbose_mode(self):

        # Get implemented test cases and check their values
        tcs = self.analyzer.get_implemented_testcases(verbose=True)
        self.struct_validator.check_tc_from_analyzer(tcs)

        # Check that they have the extra informations (the source code)
        for tc in tcs:
            self.assertGreater(len(tc[2]), 0)

    def test_get_implemented_testcases_single_test_case_which_bugged(self):

        if self.TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST:
            # Get implemented test cases and check their values
            tcs = self.analyzer.get_implemented_testcases(
                [self.TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST]
            )
            self.struct_validator.check_tc_from_analyzer(tcs)
            self.assertEqual(len(tcs), 1)
            self.assertEqual(tcs[0][0], self.TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST)

    def test_get_implemented_testcases_unknown_test_case(self):

        # Get implemented test cases and check their values
        with self.assertRaises(FileNotFoundError):
            tcs = self.analyzer.get_implemented_testcases(
                [self.UNKNOWN_TEST_CASE_ID]
            )

    def test_get_implemented_testcases_str_instead_of_list(self):

        # Get implemented test cases and check their values
        with self.assertRaises(InputParameterError):
            tcs = self.analyzer.get_implemented_testcases(self.TEST_CASE_ID)

    # ##### analyse
    def test_analyse_basic_pass_PCAPs(self):
        dir = self.TEST_DIR
        print('looking for test dumps for testing the test cases: %s' % dir)
        for tc in self.analyzer.get_implemented_testcases():
            filename = path.join(dir, tc[0] + '_PASS.pcap')
            print('Testcase found %s , dump file %s for test exist: %s' % (str(tc[0]), filename, path.isfile(filename)))
            # check if there's a pcap_pass_test for the testcase
            if path.isfile(filename):
                tc_name, verdict, rev_frames, log, partial_verdicts, exception_info = self.analyzer.analyse(filename,
                                                                                                            tc[0])

                # I apologize to you future reader for the utterly ugly way of unpacking the exception info :)
                exc_str = ''
                if exception_info:
                    counter = 0
                    for i in exception_info:
                        counter += 1
                        exc_str += '\nException n:%s' % counter
                        exc_str += '\n\ttype: %s ' % i[0]
                        exc_str += '\n\texception: %s' % i[1]
                        exc_str += '\n\ttracelog: %s' % i[2]
                        exc_str += '\n'

                self.assertTrue(verdict == 'pass',
                                msg='%s implementation got verdict: %s expected PASS \n '
                                    'details: \n %s \n'
                                    'errors: \n %s \n'
                                    'logs: \n %s \n'
                                    %
                                    (
                                        tc_name,
                                        str(verdict).upper(),
                                        json.dumps(partial_verdicts, indent=4) if log else "",
                                        exc_str if exc_str else "No exception registered",
                                        log
                                    )
                                )

                print('Testcase %s , got verdict: %s' % (str(tc[0]), str(verdict).upper()))


class SixlowpanHcAnalyzerTestCase(CoAPAnalyzerTestCase):
    # #################### Tests parameters #########################
    TEST_ENV = 'tat_6lowpan'
    TEST_DIR = './tests/test_dumps/6lowpan_hc/'
    UNKNOWN_TEST_ENV = 'unknown'
    TEST_CASE_ID = 'TD_6LOWPAN_HC_01'
    UNKNOWN_TEST_CASE_ID = 'TD_6LOWPAN_HC_666'
    TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST = None


class LwM2MPRO_AnalyzerTestCase(CoAPAnalyzerTestCase):
    # #################### Tests parameters #########################
    TEST_ENV = 'tat_lwm2m'
    TEST_DIR = './tests/test_dumps/lwm2m_pro/'
    UNKNOWN_TEST_ENV = 'unknown'
    TEST_CASE_ID = 'TD_LWM2M_1_INT_204'
    UNKNOWN_TEST_CASE_ID = 'asdasd'
    TEST_CASE_ID_WHICH_BUGGED_IN_THE_PAST = None


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
