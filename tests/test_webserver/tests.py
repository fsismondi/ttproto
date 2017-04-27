import unittest
import json
import http.server
import os
import threading
import requests
import base64
import hashlib

from ttproto.ts_coap import webserver
from ttproto.ts_coap.webserver import *


class WebserverTestCase(unittest.TestCase):
    """
        Test case for the Webserver
        Mostly of the API calls
    """

    # #################### Tests parameters #########################

    # Webserver binding
    SERVER_ADDRESS = '0.0.0.0'
    SERVER_PORT = 8008
    TAT_API_URL = 'http://127.0.0.1:' + str(SERVER_PORT)
    FILES_DIR = 'tests/test_files'

    # Accepted values for some fields
    VERDICT_VALUES = [None, "inconclusive", "pass", "fail", "error"]

    # Some dummy values
    EXISTING_TEST_CASE = 'TD_COAP_CORE_01'
    UNKNOWN_TEST_CASE = 'UNKNOWN_TEST_CASE'
    WRONG_TOKEN = 'ayVMgJQiQICOCqBKE7pV7qVzU6k'
    WRONG_FRAME_ID = 500
    JOKER_PROTOCOL_NAME = 'None'

    # Put some test parameters passed from one function to another
    CORRECT_TOKEN = None
    CORRECT_FRAME_ID = None

    # Structure definition of packets
    STRUCT_RESPONSE_OK = {
        '_type': str,
        'ok': bool,
        'content': list
    }
    STRUCT_RESPONSE_KO = {
        '_type': str,
        'ok': bool,
        'error': str
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
    STRUCT_IMPLEMENTED_PROTOCOL = {
        '_type': str,
        'name': str,
        'description': str
    }
    STRUCT_TOKEN = {
        '_type': str,
        'value': str
    }
    STRUCT_FRAME = {
        '_type': str,
        'id': int,
        'timestamp': float,
        'error': (type(None), str),
        'protocol_stack': list
    }
    STRUCT_VERDICT = {
        '_type': str,
        'verdict': str,
        'description': str,
        'review_frames': list
    }

    # #################### Init and deinit functions #########################
    # def setUp(self):
    #     """
    #         Initialize the server on which we'll run the tests
    #         It creates a thread on which we run the server
    #     """
    #     # Put the needed log file for the webserver (it's required)
    #     webserver.log_file = open(
    #         os.path.join(LOGDIR, 'unit-tests-webserver.log'),
    #         'a'
    #     )

    #     # Create the server instance
    #     self.server = http.server.HTTPServer(
    #         (
    #             self.SERVER_ADDRESS,
    #             self.SERVER_PORT
    #         ),
    #         RequestHandler)

    #     # Make a thread to handle server requests, the main one will do tests
    #     thread = threading.Thread(target=self.server.serve_forever)
    #     thread.start()

    # def tearDown(self):
    #     """
    #         Close the server
    #     """
    #     self.server.shutdown()
    #     self.server.server_close()
    #     webserver.log_file.close()

    @classmethod
    def setUpClass(cls):
        """
            Initialize the server on which we'll run the tests
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

        # Make a thread to handle server requests, the main one will do tests
        thread = threading.Thread(target=cls.server.serve_forever)
        thread.start()

    @classmethod
    def tearDownClass(cls):
        """
            Close the server
        """
        cls.server.shutdown()
        cls.server.server_close()
        webserver.log_file.close()

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

    def check_correct_response_header(self, response):
        # Check the object type
        self.assertIsInstance(response, requests.models.Response)

        # Check the response code
        self.assertEqual(response.status_code, 200)

        # Check the headers
        self.assertEqual(
            response.headers['content-type'],
            'application/json;charset=utf-8'
        )

    def check_request_not_found_header(self, response):
        # Check the object type
        self.assertIsInstance(response, requests.models.Response)

        # Check the response code
        self.assertEqual(response.status_code, 404)

    def check_correct_response(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_RESPONSE_OK)

        # Check its values
        self.assertEqual(el['_type'], 'response')
        self.assertTrue(el['ok'])
        self.assertGreater(len(el['content']), 0)

    def check_error_response(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_RESPONSE_KO)

        # Check its values
        self.assertEqual(el['_type'], 'response')
        self.assertFalse(el['ok'])

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

    def check_implemented_protocol(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_IMPLEMENTED_PROTOCOL)

        # Check its type
        self.assertEqual(el['_type'], 'implemented_protocol')

    def check_token(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_TOKEN)

        # Check its type
        self.assertEqual(el['_type'], 'token')

        # Check that the value is a correct hash
        # Add '=' only for checking
        decoded = base64.urlsafe_b64decode(el['value'] + '=')
        self.assertEqual(len(decoded), hashlib.sha1().digest_size)

    def check_protocol(self, el):
        # Check that it's a non empty dict
        self.assertIsInstance(el, dict)
        self.assertGreater(len(el), 0)

        # Check its minimum fields
        self.assertIn('_type', el)
        self.assertIn('_protocol', el)
        self.assertEqual(el['_type'], 'protocol')

        # Check that it has more values than that
        self.assertGreater(len(el), 2)

    def check_frame(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_FRAME)

        # Check its type
        self.assertEqual(el['_type'], 'frame')

        # Check that we have a protocol stack
        self.assertGreater(len(el['protocol_stack']), 0)
        for prot in el['protocol_stack']:
            self.check_protocol(prot)

    def check_is_int_real(self, el):
        # Check its type
        self.assertEqual(type(el), int)

        # Check its value
        self.assertGreater(el, 0)

    def check_verdict(self, el):
        # Check the structure
        self.check_correct_structure(el, self.STRUCT_VERDICT)

        # Check its type
        self.assertEqual(el['_type'], 'verdict')

        # Check that the verdict given is contained in the accepted values
        self.assertIn(el['verdict'], self.VERDICT_VALUES)

        # Check that we have some review frames
        self.assertGreaterEqual(len(el['review_frames']), 0)
        for frame in el['review_frames']:
            self.check_is_int_real(frame)

    # #################### Tests functions #########################

    # ##### get_test_cases(testcase_id=None)
    def test_get_test_cases_all_selected(self):
        test_cases = get_test_cases()
        self.assertIsInstance(test_cases, dict)
        self.assertGreater(len(test_cases), 0)
        self.assertIsInstance(test_cases, dict)

    def test_get_test_cases_all_selected_with_none_value(self):
        test_cases = get_test_cases(None)
        self.assertIsInstance(test_cases, dict)
        self.assertGreater(len(test_cases), 0)
        self.assertIsInstance(test_cases, dict)

    def test_get_test_cases_only_one_existing_test_case(self):
        test_case = get_test_cases(self.EXISTING_TEST_CASE)
        self.assertIsInstance(test_case, dict)
        self.assertEqual(len(test_case), 2)

        # Check that we received a correct element
        self.assertIn('tc_basic', test_case)
        self.check_tc_basic(test_case['tc_basic'])

        self.assertIn('tc_implementation', test_case)
        self.check_tc_implementation(test_case['tc_implementation'])

    def test_get_test_cases_only_one_unknown_test_case(self):
        test_case = get_test_cases(self.UNKNOWN_TEST_CASE)
        self.assertIsNone(test_case)

    # -------------------------------------------------------------------------------

    # ##### analyzer_getTestCases
    def test_analyzer_get_test_cases(self):

        # Execute the request
        resp = requests.get(self.TAT_API_URL + '/api/v1/analyzer_getTestCases')

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the content only contains tc_basic
        self.assertGreater(len(resp['content']), 0)
        for content in resp['content']:
            self.check_tc_basic(content)

    # -------------------------------------------------------------------------------

    # ##### analyzer_getTestcaseImplementation
    def test_analyzer_get_testcase_implementation(self):

        # Prepare GET parameters
        params = {'testcase_id': self.EXISTING_TEST_CASE}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the content only contains a tc_implementation and a tc_basic
        self.assertEqual(len(resp['content']), 2)
        self.check_tc_basic(resp['content'][0])
        self.check_tc_implementation(resp['content'][1])

    def test_analyzer_get_testcase_implementation_no_params(self):

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation'
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects GET parameters, expected '?testcase_id={string}'"
        )

    def test_analyzer_get_testcase_implementation_wrong_params(self):

        # Prepare GET parameters
        params = {'wrong_param_name': self.EXISTING_TEST_CASE}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects GET parameters, expected '?testcase_id={string}'"
        )

    def test_analyzer_get_testcase_implementation_more_params(self):

        # Prepare GET parameters
        params = {
            'testcase_id': self.EXISTING_TEST_CASE,
            'another_param_not_wanted': 'this_param_is_unwanted'
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects GET parameters, expected '?testcase_id={string}'"
        )

    def test_analyzer_get_testcase_implementation_post_data_instead_of_get(self):

        # Prepare GET parameters
        params = {'testcase_id': self.EXISTING_TEST_CASE}

        # Execute the request with the params as POST and not GET params
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            data=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects GET parameters, expected '?testcase_id={string}'"
        )

    def test_analyzer_get_testcase_implementation_post_and_get_data(self):

        # Prepare GET parameters
        params = {'testcase_id': self.EXISTING_TEST_CASE}

        # Execute the request with the params as POST and not GET params
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            data=params,
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # It passes but in practice there is no POST values into a GET request

        # Check the content only contains a tc_implementation and a tc_basic
        self.assertEqual(len(resp['content']), 2)
        self.check_tc_basic(resp['content'][0])
        self.check_tc_implementation(resp['content'][1])

    def test_analyzer_get_testcase_implementation_unknown_test_case(self):

        # Prepare GET parameters
        params = {'testcase_id': self.UNKNOWN_TEST_CASE}

        # Execute the request with the params as POST and not GET params
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getTestcaseImplementation',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Test case %s not found' % self.UNKNOWN_TEST_CASE
        )

    # -------------------------------------------------------------------------------

    # ##### analyzer_getProtocols
    def test_analyzer_get_protocols(self):

        # Execute the request
        resp = requests.get(self.TAT_API_URL + '/api/v1/analyzer_getProtocols')

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the content only contains protocols
        self.assertGreater(len(resp['content']), 0)
        for content in resp['content']:
            self.check_implemented_protocol(content)

    # -------------------------------------------------------------------------------

    # ##### analyzer_getFrames
    def test_analyzer_get_frames(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.assertEqual(resp['content'][0]['value'], CORRECT_TOKEN)
        self.check_frame(resp['content'][1])
        self.assertEqual(resp['content'][1]['id'], CORRECT_FRAME_ID)

    def test_analyzer_get_frames_no_params(self):

        # Execute the request
        resp = requests.get(self.TAT_API_URL + '/api/v1/analyzer_getFrames')

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_only_token(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {'token': CORRECT_TOKEN}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_only_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {'frame_id': CORRECT_FRAME_ID}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_only_protocol_selection(self):

        # Prepare GET parameters
        params = {'protocol_selection': self.JOKER_PROTOCOL_NAME}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_only_token_and_protocol_selection(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertGreaterEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.assertEqual(resp['content'][0]['value'], CORRECT_TOKEN)

        # Check each following frames
        for i in range(1, len(resp['content'])):
            self.check_frame(resp['content'][i])

    def test_analyzer_get_frames_token_and_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_protocol_selection_and_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_frame_id_not_integer(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': 'definitively_not_an_integer'
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_frame_id_negative(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': -42
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_more_params(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': CORRECT_FRAME_ID,
            'testcase_id': self.EXISTING_TEST_CASE
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_analyzer_get_frames_post_and_get_data(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': CORRECT_FRAME_ID
        }

        # Execute the request with the params as POST and not GET params
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            data=params,
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # It passes but in practice there is no POST values into a GET request

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.check_frame(resp['content'][1])

    def test_analyzer_get_frames_wrong_token(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': self.WRONG_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Session identified by token %s not found' % self.WRONG_TOKEN
        )

    def test_analyzer_get_frames_wrong_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': self.WRONG_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'No frame with id=%u found' % self.WRONG_FRAME_ID
        )

    def test_analyzer_get_frames_wrong_protocol_selection(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': 'WrongProtocolSelection'
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/analyzer_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Unknown %s protocol' % 'WrongProtocolSelection'
        )

    # TODO
    # After the protocol selection is implemented, check that we only receive
    # frames of this protocol and not others anymore

    # -------------------------------------------------------------------------------

    # ##### dissector_getFrames
    def test_dissector_get_frames(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.assertEqual(resp['content'][0]['value'], CORRECT_TOKEN)
        self.check_frame(resp['content'][1])
        self.assertEqual(resp['content'][1]['id'], CORRECT_FRAME_ID)

    def test_dissector_get_frames_no_params(self):

        # Execute the request
        resp = requests.get(self.TAT_API_URL + '/api/v1/dissector_getFrames')

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_only_token(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {'token': CORRECT_TOKEN}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_only_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {'frame_id': CORRECT_FRAME_ID}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_only_protocol_selection(self):

        # Prepare GET parameters
        params = {'protocol_selection': self.JOKER_PROTOCOL_NAME}

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_only_token_and_protocol_selection(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertGreaterEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.assertEqual(resp['content'][0]['value'], CORRECT_TOKEN)

        # Check each following frames
        for i in range(1, len(resp['content'])):
            self.check_frame(resp['content'][i])

    def test_dissector_get_frames_token_and_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_protocol_selection_and_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_frame_id_not_integer(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': 'definitively_not_an_integer'
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_frame_id_negative(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': -42
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_more_params(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': CORRECT_FRAME_ID,
            'testcase_id': self.EXISTING_TEST_CASE
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
        )

    def test_dissector_get_frames_post_and_get_data(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'frame_id': CORRECT_FRAME_ID
        }

        # Execute the request with the params as POST and not GET params
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            data=params,
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # It passes but in practice there is no POST values into a GET request

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])
        self.check_frame(resp['content'][1])

    def test_dissector_get_frames_wrong_token(self):

        # Check params that we normally should get from last dissect
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': self.WRONG_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Session identified by token %s not found' % self.WRONG_TOKEN
        )

    def test_dissector_get_frames_wrong_frame_id(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': self.WRONG_FRAME_ID,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'No frame with id=%u found' % self.WRONG_FRAME_ID
        )

    def test_dissector_get_frames_wrong_protocol_selection(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        global CORRECT_FRAME_ID
        self.assertIsNotNone(CORRECT_TOKEN)
        self.assertIsNotNone(CORRECT_FRAME_ID)

        # Prepare GET parameters
        params = {
            'token': CORRECT_TOKEN,
            'frame_id': CORRECT_FRAME_ID,
            'protocol_selection': 'WrongProtocolSelection'
        }

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getFrames',
            params=params
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Unknown %s protocol' % 'WrongProtocolSelection'
        )

    # TODO
    # After the protocol selection is implemented, check that we only receive
    # frames of this protocol and not others anymore

    # -------------------------------------------------------------------------------

    # ##### dissector_getProtocols
    def test_dissector_get_protocols(self):

        # Execute the request
        resp = requests.get(
            self.TAT_API_URL + '/api/v1/dissector_getProtocols'
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the content only contains protocols
        self.assertGreater(len(resp['content']), 0)
        for content in resp['content']:
            self.check_implemented_protocol(content)

    # -------------------------------------------------------------------------------

    # ##### do_GET handler
    def test_do_get_handler_not_found(self):

        # Execute a request on an unknown path
        resp = requests.get(self.TAT_API_URL + '/api/v1/unknow_path')
        self.check_request_not_found_header(resp)

    # -------------------------------------------------------------------------------

    # ##### analyzer_testCaseAnalyze
    def test_analyzer_test_case_analyze_from_pcap(self):

        # Prepare POST parameters
        datas = {'testcase_id': self.EXISTING_TEST_CASE}

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 3)
        self.check_token(resp['content'][0])
        self.check_tc_basic(resp['content'][1])
        self.check_verdict(resp['content'][2])

        # Check that the verdict is correct too
        self.assertEqual(resp['content'][2]['verdict'], 'pass')

    def test_analyzer_test_case_analyze_from_token(self):

        # Check params that we normally should get from last dissect
        global CORRECT_TOKEN
        self.assertIsNotNone(CORRECT_TOKEN)

        # Prepare POST parameters
        datas = {
            'testcase_id': self.EXISTING_TEST_CASE,
            'token': CORRECT_TOKEN
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 3)
        self.check_token(resp['content'][0])
        self.assertEqual(resp['content'][0]['value'], CORRECT_TOKEN)
        self.check_tc_basic(resp['content'][1])
        self.check_verdict(resp['content'][2])

        # Check that the verdict is correct too
        self.assertEqual(resp['content'][2]['verdict'], 'pass')

    def test_analyzer_test_case_analyze_no_post_datas(self):

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data={}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Non empty POST datas and format of 'multipart/form-data' expected"
        )

    def test_analyzer_test_case_analyze_only_testcase_id(self):

        # Prepare POST parameters
        datas = {'testcase_id': self.EXISTING_TEST_CASE}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_only_pcap_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data={},
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_only_token(self):

        # Prepare POST parameters
        datas = {'token': self.WRONG_TOKEN}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_both_token_and_pcap_file(self):

        # Prepare POST parameters
        datas = {'token': self.WRONG_TOKEN}

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_all_the_three(self):

        # Prepare POST parameters
        datas = {
            'token': self.WRONG_TOKEN,
            'testcase_id': self.EXISTING_TEST_CASE
        }

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_with_get_parameters(self):

        # Prepare POST parameters
        datas = {
            'token': self.WRONG_TOKEN,
            'testcase_id': self.EXISTING_TEST_CASE
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            params=datas
        )

        # Check headers
        self.check_request_not_found_header(resp)

    def test_analyzer_test_case_analyze_pcap_file_not_a_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'token': self.WRONG_TOKEN,
            'testcase_id': self.EXISTING_TEST_CASE,
            'pcap_file': pcap_path
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_pcap_file_in_file_but_not_a_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'token': self.WRONG_TOKEN,
            'testcase_id': self.EXISTING_TEST_CASE
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files={'pcap_file': pcap_path}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
        )

    def test_analyzer_test_case_analyze_unknown_testcase_id(self):

        # Prepare POST parameters
        datas = {
            'testcase_id': self.UNKNOWN_TEST_CASE
        }

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Test case %s not found' % self.UNKNOWN_TEST_CASE
        )

    def test_analyzer_test_case_analyze_pcap_then_token(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'testcase_id': self.EXISTING_TEST_CASE
        }
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp['content']), 3)
        self.check_token(resp['content'][0])
        self.check_tc_basic(resp['content'][1])
        self.check_verdict(resp['content'][2])

        # Check that the verdict is correct too
        self.assertEqual(resp['content'][2]['verdict'], 'pass')

        # Then do the same request with the token
        datas = {
            'testcase_id': self.EXISTING_TEST_CASE,
            'token': resp['content'][0]['value']
        }

        # Execute the request
        resp_token = requests.post(
            self.TAT_API_URL + '/api/v1/analyzer_testCaseAnalyze',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp_token)

        # Check data headers
        resp_token = resp_token.json()
        self.check_correct_response(resp_token)

        # Check the response contains a token and a frame
        self.assertEqual(len(resp_token['content']), 3)
        self.check_token(resp_token['content'][0])
        self.check_tc_basic(resp_token['content'][1])
        self.check_verdict(resp_token['content'][2])

        # Check that the verdict is correct too
        self.assertEqual(resp_token['content'][2]['verdict'], 'pass')

        # Check both of the responses
        self.assertEqual(resp, resp_token)

    # -------------------------------------------------------------------------------

    # ##### dissector_dissectFile

    # The a is a little hack for this function to be the first tested
    # in order to get a valid token for the following test suite
    def test_01_dissector_dissect_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data={'protocol_selection': self.JOKER_PROTOCOL_NAME},
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_correct_response(resp)

        # Check the response contains a token
        self.assertGreaterEqual(len(resp['content']), 2)
        self.check_token(resp['content'][0])

        # Get the token then
        global CORRECT_TOKEN
        CORRECT_TOKEN = resp['content'][0]['value']

        # And many frames
        for i in range(1, len(resp['content'])):
            self.check_frame(resp['content'][i])

        # Get the last frame_id
        global CORRECT_FRAME_ID
        CORRECT_FRAME_ID = resp['content'][i]['id']

    def test_dissector_dissect_file_no_post_datas(self):

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data={}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Non empty POST datas and format of 'multipart/form-data' expected"
        )

    def test_dissector_dissect_file_only_protocol_selection(self):

        # Prepare POST parameters
        datas = {'protocol_selection': self.JOKER_PROTOCOL_NAME}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
        )

    def test_dissector_dissect_file_only_pcap_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data={},
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Expected POST=(pcap_file={file}, protocol_selection={text})'
        )

    def test_dissector_dissect_file_with_get_parameters(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'pcap_file': pcap_path,
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas,
            params=datas
        )

        # Check headers
        self.check_request_not_found_header(resp)

    def test_dissector_dissect_file_pcap_file_not_a_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'protocol_selection': self.JOKER_PROTOCOL_NAME,
            'pcap_file': pcap_path
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
        )

    def test_dissector_dissect_file_pcap_file_in_file_but_not_a_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )

        # Prepare POST parameters
        datas = {
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas,
            files={'pcap_file': pcap_path}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Expected 'pcap_file' to be a non empty pcap file"
        )

    def test_dissector_dissect_file_pcap_file_in_file_but_not_a_pcap_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s" % (
            self.FILES_DIR,
            'WrongFilesForTests',
            'not_a_pcap_file.dia'
        )

        # Prepare POST parameters
        datas = {
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas,
            files={'pcap_file': pcap_path}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Expected 'pcap_file' to be a non empty pcap file"
        )

    def test_dissector_dissect_file_empty_pcap_file(self):

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            'WrongFilesForTests',
            'empty_pcap'
        )

        # Prepare POST parameters
        datas = {
            'protocol_selection': self.JOKER_PROTOCOL_NAME
        }

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas,
            files={'pcap_file': pcap_path}
        )

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            "Expected 'pcap_file' to be a non empty pcap file"
        )

    def test_dissector_dissect_file_unknown_protocol_selection(self):

        # Prepare POST parameters
        datas = {
            'protocol_selection': 'unknown_protocol_selection'
        }

        # Get the path of the pcap file
        pcap_path = "%s/%s/%s.pcap" % (
            self.FILES_DIR,
            self.EXISTING_TEST_CASE,
            'pass'
        )
        files = {'pcap_file': open(pcap_path, 'rb')}

        # Execute the request
        resp = requests.post(
            self.TAT_API_URL + '/api/v1/dissector_dissectFile',
            data=datas,
            files=files
        )

        # Close the file
        files['pcap_file'].close()

        # Check headers
        self.check_correct_response_header(resp)

        # Check data headers
        resp = resp.json()
        self.check_error_response(resp)

        # Check the content is an error message
        self.assertEqual(
            resp['error'],
            'Unknown protocol unknown_protocol_selection'
        )

    # -------------------------------------------------------------------------------

    # ##### do_POST handler
    def test_do_post_handler_not_found(self):

        # Execute a request on an unknown path
        resp = requests.post(self.TAT_API_URL + '/api/v1/unknow_path')
        self.check_request_not_found_header(resp)


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
