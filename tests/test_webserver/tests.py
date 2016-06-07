import unittest
import json
import http.server
import os
import threading
import requests
from collections import OrderedDict

from ttproto.ts_coap import webserver
from ttproto.ts_coap.webserver import *


class WebserverTestCase(unittest.TestCase):
    """
        Test case for the Webserver
        Mostly of the API calls
    """

    # #################### Tests parameters #########################.

    # Webserver binding
    SERVER_ADDRESS = '0.0.0.0'
    SERVER_PORT = 8008
    TAT_API_URL = 'http://127.0.0.1:' + str(SERVER_PORT)

    # Some test cases
    EXISTING_TEST_CASE = 'TD_COAP_CORE_04'
    UNKNOWN_TEST_CASE = 'UNKNOWN_TEST_CASE'

    # Structure definition of packets
    STRUCT_RESPONSE = {
        '_type': str,
        'ok': bool,
        'content': list
    }
    STRUCT_TC_BASIC = {
        '_type': str,
        'id': str,
        'objective': str
    }
    STRUCT_TC_IMPLEMENTATION = {
        '_type': str,
        'implementation': str
    }

    # #################### Init and deinit functions #########################
    @classmethod
    def setUpClass(cls):
        """
            Initialize the server on which we'll run the testes
            It creates a thread on which we run the server
        """
        # Put the needed log file for the webserver (it's required)
        webserver.log_file = open(
            os.path.join(LOGDIR, 'unit-tests-webserver.log'),
            'a'
        )

        # Create the server instance
        cls.server = http.server.HTTPServer(
            (
                cls.SERVER_ADDRESS,
                cls.SERVER_PORT
            ),
            RequestHandler)

        # Make a thread to handle server requests, the main one will do testes
        thread = threading.Thread(target=cls.server.serve_forever)
        thread.start()

    @classmethod
    def tearDownClass(cls):
        """
            Close the server
        """
        cls.server.shutdown()
        cls.server.server_close()

    # #################### Utilities functions #########################

    def check_correct_structure(self, el, structure):
        # Check that it's a non empty dict
        self.assertIsInstance(el, dict)
        self.assertGreater(len(el), 0)

        # Check its fields
        self.assertEqual(el.keys(), structure.keys())

        # Check the type of all its fields
        for field in structure:
            self.assertIsInstance(el[field], structure[field])

    def check_tc_basic(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_TC_BASIC)

        # Check its type
        self.assertEqual(el['_type'], 'tc_basic')

    def check_tc_implementation(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_TC_IMPLEMENTATION)

        # Check its type
        self.assertEqual(el['_type'], 'tc_implementation')

    def check_json_correct_response_header(self, response):
        # Check the object type
        self.assertIsInstance(response, requests.models.Response)

        # Check the response code
        self.assertEqual(response.status_code, 200)

        # Check the headers
        self.assertEqual(
            response.headers['content-type'],
            'application/json;charset=utf-8'
        )

    def check_correct_response_data_header(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_RESPONSE)

        # Check its values
        self.assertEqual(el['_type'], 'response')
        self.assertTrue(el['ok'])
        self.assertGreater(len(el['content']), 0)

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
        self.check_tc_basic(test_case['tc_basic'])

        self.assertIn('tc_implementation', test_case)
        self.check_tc_implementation(test_case['tc_implementation'])
    #

    def test_get_test_cases_only_one_unknown_test_case(self):
        test_case = get_test_cases(self.UNKNOWN_TEST_CASE)
        self.assertIsNone(test_case)
    #

    # -------------------------------------------------------------------------------

    # ##### testcase_getList
    def test_case_get_list(self):

        # Execute the request
        resp = requests.get(self.TAT_API_URL + '/api/v1/testcase_getList')

        # Check headers
        self.check_json_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response_data_header(resp)

        # Check the content only contains tc_basic
        for content in resp['content']:
            self.check_tc_basic(content)


# #################### Main run the testes #########################
if __name__ == '__main__':
    unittest.main()
