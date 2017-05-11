import unittest
import requests
import base64
import hashlib

from collections import OrderedDict
from ttproto.core.control import Verdict


class StructureValidator(unittest.TestCase):

    # #################### Object structures #########################
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
    VERDICT_VALUES = Verdict.values()

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

    def check_tc_from_analyzer(self, el):

        # Check that we receive a list of tuple
        self.assertEqual(type(el), list)

        for tc in el:
            self.assertEqual(type(tc), tuple)
            self.assertEqual(len(tc), 4)

            # For each element of this, it should be a string
            for tuple_el in tc:
                self.assertEqual(type(tuple_el), str)

    def check_tc_from_webserver(self, el):

        # Webserver function return an ordered dict
        self.assertEqual(type(el), OrderedDict)

        # For each couple key / value
        for key in el:

            # Get the value
            value = el[key]

            # Check that the key is a name and value a dict
            self.assertEqual(type(key), str)
            self.assertEqual(type(value), OrderedDict)

            # Check the fields of value
            self.assertEqual(len(value), 2)
            self.assertIn('tc_basic', value)
            self.assertIn('tc_implementation', value)

            # Check the two fields then
            self.check_tc_basic(value['tc_basic'])
            self.check_tc_implementation(value['tc_implementation'])
