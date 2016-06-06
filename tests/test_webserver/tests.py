import unittest
import json
from collections import OrderedDict
from ttproto.ts_coap.webserver import get_test_cases


class WebserverTestCase(unittest.TestCase):
    """
        Test case for the Webserver
        Mostly of the API calls
    """

    # #################### Tests parameters #########################.

    EXISTING_TEST_CASE = 'TD_COAP_CORE_04'
    UNKNOWN_TEST_CASE = 'UNKNOWN_TEST_CASE'

    # #################### Tests functions #########################

    # ##### get_test_cases(testcase_id=None)

    def test_get_test_cases_all_selected(self):
        test_cases = get_test_cases()
        self.assertIsInstance(test_cases, dict)
        self.assertGreater(len(test_cases), 0)

        # To remove if the type of it is changed
        self.assertIsInstance(test_cases, OrderedDict)
    #

    def test_get_test_cases_all_selected_with_none_value(self):
        test_cases = get_test_cases(None)
        self.assertIsInstance(test_cases, dict)
        self.assertGreater(len(test_cases), 0)

        # To remove if the type of it is changed
        self.assertIsInstance(test_cases, OrderedDict)
    #

    def test_get_test_cases_only_one_existing_test_case(self):
        test_case = get_test_cases(self.EXISTING_TEST_CASE)
        self.assertIsInstance(test_case, dict)
        self.assertEqual(len(test_case), 2)

        # Check that we received a correct element
        self.assertIn('tc_basic', test_case)
        self.assertIsInstance(test_case['tc_basic']['_type'], str)
        self.assertEqual(test_case['tc_basic']['_type'], 'tc_basic')
        self.assertIsInstance(test_case['tc_basic']['id'], str)
        self.assertIsInstance(test_case['tc_basic']['objective'], str)

        self.assertIn('tc_implementation', test_case)
        self.assertIsInstance(test_case['tc_implementation']['_type'], str)
        self.assertEqual(
            test_case['tc_implementation']['_type'],
            'tc_implementation'
        )
        self.assertIsInstance(
            test_case['tc_implementation']['implementation'],
            str
        )
    #

    def test_get_test_cases_only_one_unknown_test_case(self):
        test_case = get_test_cases(self.UNKNOWN_TEST_CASE)
        self.assertIsNone(test_case)
    #


# #################### Main run the testes #########################
if __name__ == '__main__':
    unittest.main()
