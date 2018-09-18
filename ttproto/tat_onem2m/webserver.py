#!/usr/bin/env python3
#
#  (c) 2012  Universite de Rennes 1
#
# Contact address: <t3devkit@irisa.fr>
#
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

import http.server
import io
import sys
import os
import errno
import re
import time
import signal
import cgi
import json
import hashlib
import base64
import logging

from collections import OrderedDict
from urllib.parse import urlparse, parse_qs
from ttproto.utils import pure_pcapy
from ttproto.core.analyzer import Analyzer
from ttproto.core.dissector import Dissector
from ttproto.core.typecheck import typecheck,optional,either,list_of
from ttproto.core.lib.all import *
from ttproto.core.lib.readers.yaml import YamlReader

# Directories
from ttproto import DATADIR
from ttproto import TMPDIR
from ttproto import LOGDIR


# Prefix and suffix for the hashes
HASH_PREFIX = 'tt'
HASH_SUFFIX = 'proto'
TOKEN_LENGTH = 28

# The different implemented protocols
PROTOCOLS = OrderedDict()

job_id = 0

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# This is PoC of a RPC-like API over http (and not a REST api!) #
# The official and supported API is the AMQP one                #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

logger = logging.getLogger(__name__)

@typecheck
def get_test_cases(
    testcase_id: optional(str) = None,
    verbose: bool = False
) -> OrderedDict:
    """
    Function to get the implemented test cases

    :param testcase_id: The id of the single test case if one wanted
    :param verbose: True if we want a verbose response
    :type testcase_id: str
    :type verbose: bool

    :return: The implemented test cases using doc.f-interop.eu format
    :rtype: OrderedDict
    """

    test_cases = OrderedDict()
    tc_query = [] if not testcase_id else [testcase_id]
    raw_tcs = Analyzer('tat_coap').get_implemented_testcases(
        tc_query,
        verbose
    )

    # Build the clean results list
    for raw_tc in raw_tcs:

        tc_basic = OrderedDict()
        tc_basic['_type'] = 'tc_basic'
        tc_basic['id'] = raw_tc[0]
        tc_basic['objective'] = raw_tc[1]

        tc_implementation = OrderedDict()
        tc_implementation['_type'] = 'tc_implementation'
        tc_implementation['implementation'] = raw_tc[2]

        # Tuple, basic + implementation
        test_cases[raw_tc[0]] = OrderedDict()
        test_cases[raw_tc[0]]['tc_basic'] = tc_basic
        test_cases[raw_tc[0]]['tc_implementation'] = tc_implementation

    # If a single element is asked
    if testcase_id:
        test_cases = test_cases[raw_tcs[0][0]]

    # Return the results
    return test_cases


@typecheck
def get_protocol(
    protocol: optional(str) = None
) -> either(OrderedDict, type(None)):
    """
    Function to get the protocols

    :param protocol: The name of the protocol
    :type protocol: str

    :return: The implemented protocols, or a single one
    :rtype: OrderedDict
    """

    # Get the global variable to store the protocols
    global PROTOCOLS

    # If empty for the moment
    if len(PROTOCOLS) == 0:

        # Put the 'None' protocol which get everything
        PROTOCOLS['None'] = OrderedDict()
        PROTOCOLS['None']['_type'] = 'implemented_protocol'
        PROTOCOLS['None']['name'] = 'None'
        PROTOCOLS['None']['description'] = ''

        # Getter of protocol's classes from dissector
        prot_classes = Dissector.get_implemented_protocols()

        # Build the clean results list
        for prot_class in prot_classes:

            # Put the protocol
            prot = OrderedDict()
            prot['_type'] = 'implemented_protocol'
            prot['name'] = prot_class.__name__
            prot['description'] = ''

            # Add it to protocol variable
            PROTOCOLS[prot['name']] = prot

    # If there's only one protocol asked
    if protocol is not None:
        if protocol in PROTOCOLS:
            return PROTOCOLS[protocol]
        else:
            return None

    # Rerurn the protocols
    else:
        return PROTOCOLS


@typecheck
def correct_get_param(par: list, is_number: optional(bool) = False) -> bool:
    """
    Function to check if a get parameter is correct

    :param par: The get parameter to check (care it's a list)
    :param is_number: If we expect it to be a number
    :type par: list
    :type is_number: bool

    :return: True if the get parameter is correct, False if not
    :rtype: bool
    """
    return all((
        len(par) == 1,
        type(par[0]) == str,
        par[0] != '',
        not (
            is_number and (
                not par[0].isdigit() or int(par[0]) <= 0
            )
        )
    ))


@typecheck
def get_token(tok: optional(str) = None):
    """
    Function to get a token, if there's a valid one entered just return it
    otherwise generate a new one

    :param tok: The token if there's already one
    :type tok: str

    :return: A token, the same if there's already one, a new one otherwise
    :rtype: str
    """

    # If the token is already a correct one
    try:
        if all((
            tok,
            type(tok) == str,
            len(tok) == 28,
            base64.urlsafe_b64decode(tok + '=')  # Add '=' only for checking
        )):
            return tok
    except:  # If the decode throw an error => Wrong base64
        pass

    # Generate a token because there is none
    token = hashlib.sha1(
        str.encode((
            "%s%s%04d%s" %
            (
                HASH_PREFIX,
                time.time(),
                job_id,
                HASH_SUFFIX
            )
        ), encoding='utf-8')
    )
    token = base64.urlsafe_b64encode(token.digest()).decode()

    # Remove the '=' at the end of it, it is used by base64 for padding
    return token.replace('=', '')


@typecheck
def get_test_steps(tc: str) -> list_of(OrderedDict):
    """
    Get an OrderedDict representing the different steps of a test case

    :param tc: The id of the test case
    :type tc: str

    :return: The steps of a TC as a list of OrderedDict
    :rtype: [OrderedDict]
    """

    # The return list of OrderedDict
    steps = []

    # Get the test case informations
    raw_tcs = Analyzer('tat_coap').get_implemented_testcases([tc], True)
    assert len(raw_tcs) == 1

    # Parse the documentation with yaml reader and get it as dictionnary
    doc_reader = YamlReader(raw_tcs[0][3], raw_text=True)
    doc_dict = doc_reader.as_dict

    # For every step, put its informations inside the steps dict
    for step_id, step in enumerate(doc_dict[tc]['seq']):
        step_dict = OrderedDict()
        step_dict['_type'] = 'step'
        step_dict['step_id'] = step_id
        step_dict['step_type'], step_dict['step_info'] = step.popitem()
        steps.append(step_dict)

    # Return the step list of this tc
    return steps


class RequestHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args, append=""):
        host = self.address_string()
        if host in("172.17.42.1", "localhost", "127.0.0.1", "::1"):
            xff = self.headers.get("x-forwarded-for")
            if xff:
                host = xff

        txt = ("%s - - [%s] %s - %s\n%s" %
               (host,
                self.log_date_time_string(),
                format % args,
                self.headers.get("user-agent"),
                "".join("\t%s\n" % l for l in append.splitlines()),
                ))

        sys.stderr.write(txt)
        logger.info(txt)

    def api_error(self, message):
        """
            Function for generating a json error
            The error message is logged at the same time
        """
        self.log_message("%s error: %s", self.path, message)
        to_dump = OrderedDict()
        to_dump['_type'] = 'response'
        to_dump['ok'] = False
        to_dump['error'] = message
        print(json.dumps(to_dump))

    def do_GET(self):

        # Get the url and parse it
        url = urlparse(self.path)

        # ##### Personnal remarks
        #
        # For the moment, using this webserver is right but for scaling maybe a
        # strong web platform using a framework will be better. This one is
        # sufficient for the moment.
        #
        # We check on the path for whole uri, maybe we should bind a version to
        # a beginning like "/api/v1" and then bind the methods put behind it.
        #
        # ##### End of remarks

        # GET handler for the analyzer_getTestCases uri
        # It will give to the gui the list of the test cases
        #
        if url.path == '/api/v1/analyzer_getTestCases':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the list of test cases
            try:
                test_cases = get_test_cases()
            except FileNotFoundError as fnfe:
                self.api_error(
                    'Problem during fetching the test cases list:\n' + str(fnfe)
                )
                return

            clean_test_cases = []
            for tc in test_cases:
                clean_test_cases.append(test_cases[tc]['tc_basic'])

            # If no test case found
            if len(clean_test_cases) == 0:
                self.api_error('No test cases found')
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = clean_test_cases

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getTestcaseImplementation uri
        # It will allow developpers to get the implementation script of a TC
        #
        # /param testcase_id => The unique id of the test case
        #
        elif url.path == '/api/v1/analyzer_getTestCaseImplementation':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)

            try:

                # Check parameters
                if any((
                    len(params) != 1,
                    'testcase_id' not in params,
                    not correct_get_param(params['testcase_id'])
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects GET parameters, expected '?testcase_id={string}'"
                )
                return

            # Get the test case
            try:
                test_case = get_test_cases(params['testcase_id'][0], True)
            except FileNotFoundError:
                self.api_error(
                    'Test case %s not found' % params['testcase_id'][0]
                )
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = [
                test_case['tc_basic'],
                test_case['tc_implementation']
            ]

            # Here the process from ttproto core
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getTestcaseSteps uri
        # It will give the different steps of a TC
        #
        # /param testcase_id => The unique id of the test case
        #
        elif url.path == '/api/v1/analyzer_getTestcaseSteps':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)

            try:

                # Check parameters
                if any((
                    len(params) != 1,
                    'testcase_id' not in params,
                    not correct_get_param(params['testcase_id'])
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects GET parameters, expected '?testcase_id={string}'"
                )
                return

            # Get the test case
            try:
                tc_id = params['testcase_id'][0]
                steps = get_test_steps(tc_id)
            except:
                self.api_error(
                    'Steps of test case %s not found' % tc_id
                )
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = steps

            # Here the process from ttproto core
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getProtocols uri
        # It will give to the gui the list of the protocols implemented
        #
        elif url.path in (
            '/api/v1/analyzer_getProtocols',
            '/api/v1/dissector_getProtocols'
        ):

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = []

            # Get the protocols
            protocols = get_protocol()
            for prot in protocols:
                json_result['content'].append(protocols[prot])

            # Just give the json representation of the test cases list
            print(json.dumps(json_result))
            return

        # GET handler for the analyzer_getFrames and dissector_getFrames uri
        # It will allow an user to get a single frame from the previous pcap
        # if no frame_id provided, otherwise it will return all the frames
        #
        # /param token => The token of the corresponding pcap file
        # /param protocol_selection => The protocol we want to filter on
        # /param frame_id (optional) => The id of the wanted frame
        #
        # /remark We redirect to the same function but later those two
        # may diverge
        #
        elif url.path in (
            '/api/v1/analyzer_getFrames',
            '/api/v1/dissector_getFrames'
        ):

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)
            try:

                # Only token and protocol_selection
                if len(params) == 2:
                    if any((
                        'token' not in params,
                        'protocol_selection' not in params,
                        not correct_get_param(params['token']),
                        not correct_get_param(params['protocol_selection'])
                    )):
                        raise

                # token, protocol_selection and frame_id
                elif len(params) == 3:
                    if any((
                        'token' not in params,
                        'protocol_selection' not in params,
                        'frame_id' not in params,
                        not correct_get_param(params['token']),
                        not correct_get_param(params['frame_id'], is_number=True),
                        not correct_get_param(params['protocol_selection'])
                    )):
                        raise

                # Wrong number of parameters
                else:
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects parameters expected '?token={string}&protocol_selection={string}(&frame_id={integer})?'"
                )
                return

            # Format the id before passing it to the process function
            token = params['token'][0]
            protocol_selection = params['protocol_selection'][0]

            # Check the protocol
            protocol = get_protocol(protocol_selection)
            if protocol is None:
                self.api_error(
                    'Unknown %s protocol' % protocol_selection
                )
                return

            # Create the frames object
            frames = []

            # Get the json file
            try:
                json_path = os.path.join(
                    TMPDIR,
                    "%s.json" % token
                )
                with open(json_path, 'r') as json_fp:
                    frames = json.load(json_fp, object_pairs_hook=OrderedDict)
            except:
                self.api_error(
                    'Session identified by token %s not found' % token
                )
                return

            # If a single file asked
            if len(params) == 3:
                frame_id = int(params['frame_id'][0])
                for frame in frames:
                    if frame['id'] == frame_id:
                        frames = [frame]

                # If no frame with this id
                if len(frames) != 1:
                    self.api_error(
                        'No frame with id=%u found' % frame_id
                    )
                    return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            frames.insert(0, token_res)

            json_result['content'] = frames

            # Dump the json result
            print(json.dumps(json_result))
            return

        # GET handler for the dissector_getFramesSummary uri
        # It will allow an user to get all the frames summary
        #
        # /param token => The token of the corresponding pcap file
        # /param protocol_selection => The protocol we want to filter on
        #
        elif url.path == '/api/v1/dissector_getFramesSummary':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the parameters
            params = parse_qs(url.query)
            try:

                # Only token and protocol_selection
                if any((
                    len(params) != 2,
                    'token' not in params,
                    'protocol_selection' not in params,
                    not correct_get_param(params['token']),
                    not correct_get_param(params['protocol_selection'])
                )):
                    raise

            # Catch errors (key mostly) or if wrong parameter
            except:
                self.api_error(
                    "Incorrects parameters expected '?token={string}&protocol_selection={string}'"
                )
                return

            # Format the id before passing it to the process function
            token = params['token'][0]
            protocol_selection = params['protocol_selection'][0]

            # Check the protocol
            protocol = get_protocol(protocol_selection)
            if protocol is None:
                self.api_error(
                    'Unknown %s protocol' % protocol_selection
                )
                return

            # Get the dump file
            pcap_path = os.path.join(
                TMPDIR,
                "%s.dump" % token
            )
            try:
                # Get summaries from it
                frames_summary = Dissector(pcap_path).summary(
                    eval(protocol['name'])
                )
            except TypeError as e:
                self.api_error('Dissector error:\n' + str(e))
                return
            except:
                self.api_error(
                    'Session identified by token %s not found' % token
                )
                return

            # The result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token
            json_result['content'] = []
            json_result['content'].append(token_res)

            # Add each frame summary
            for f_id, f_sum in frames_summary:
                summary = OrderedDict()
                summary['_type'] = 'frame_summary'
                summary['frame_id'] = f_id
                summary['frame_summary'] = f_sum
                json_result['content'].append(summary)

            # Dump the json result
            print(json.dumps(json_result))
            return

        else:
            self.send_error(404)
            return

    def do_POST(self):

        # The job counter
        global job_id
        job_id += 1

        # ########################## ttproto API ########################### #

        # POST handler for the analyzer_testCaseAnalyze uri
        # It will allow users to analyze a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to analyze
        # \param token => The token previously provided
        # \param testcase_id => The id of the corresponding test case
        # The pcap_file or the token is required, having both is also forbidden
        #
        if self.path == '/api/v1/analyzer_testCaseAnalyze':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            try:
                content_type = cgi.parse_header(self.headers['Content-Type'])
            except TypeError:
                self.api_error(
                    "Non empty POST datas and format of 'multipart/form-data' expected"
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                keep_blank_values=True,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type[0]
                })

            # Check that we have the two values
            if any((
                len(form) != 2,
                'testcase_id' not in form,
                all((  # None of the two required => Error
                    'pcap_file' not in form,
                    'token' not in form
                )),
                all((  # Both of them => Error
                    'pcap_file' in form,
                    'token' in form
                ))
            )):
                self.api_error(
                    'Expected POST=([pcap_file={file}|token={text}], testcase_id={text})'
                )
                return

            # Get the test case and its informations
            testcase_id = form.getvalue('testcase_id')
            if not type(testcase_id) == str:
                self.api_error('The value of the testcase_id should be a string from text input')
                return

            # Try to get the test case
            try:
                test_case = get_test_cases(testcase_id)
            except FileNotFoundError:
                self.api_error('Test case %s not found' % testcase_id)
                return

            # Get the token
            token = form.getvalue('token')

            # Get analysis results from the token
            if token:

                # Just get the path
                pcap_path = os.path.join(
                    TMPDIR,
                    token + '.dump'
                )

            # Get analysis results from the pcap file
            else:

                # Check headers
                if any((
                    len(content_type) == 0,
                    content_type[0] is None,
                    content_type[0] != 'multipart/form-data'
                )):
                    self.api_error(
                        "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
                    )
                    return

                # Get the same token or generate a new one
                token = get_token(token)

                # Get and check the pcap file entered
                pcap_file = form.getvalue('pcap_file')

                # Path to save the file
                pcap_path = os.path.join(
                    TMPDIR,
                    token + '.dump'
                )

                # Write the pcap file to a temporary destination
                try:
                    with open(pcap_path, 'wb') as f:
                        f.write(pcap_file)
                except:
                    self.api_error(
                        "Couldn't write the temporary file %s"
                        %
                        pcap_path
                    )
                    return

                # Get the dissection from analysis tool
                try:
                    dissection = Dissector(pcap_path).dissect()
                except pure_pcapy.PcapError:
                    self.api_error(
                        "Expected 'pcap_file' to be a non empty pcap file"
                    )
                except:
                    self.api_error(
                        "Couldn't read the temporary file %s"
                        %
                        pcap_path
                    )
                    return

                # Save the json dissection result into a file
                json_save = os.path.join(
                    TMPDIR,
                    token + '.json'
                )
                try:
                    with open(json_save, 'w') as f:
                        json.dump(dissection, f)
                except:
                    self.api_error("Couldn't write the json file")
                    return

            # Get the result of the analysis
            analysis_results = Analyzer('tat_coap').analyse(
                                pcap_path,
                                testcase_id
                            )

            self.log_message("Analysis result: " + str(analysis_results))

            # Error for some test cases that the analysis doesn't manage to get
            try:
                assert type(analysis_results[4]) is list
                if len(analysis_results[4]) != 0:
                    assert type(analysis_results[4][0]) is tuple
                assert type(analysis_results) == tuple
                assert len(analysis_results) == 6
                assert type(analysis_results[0]) == str
                assert type(analysis_results[1]) == str
                assert type(analysis_results[2]) == list
                assert type(analysis_results[3]) == str
                assert type(analysis_results[5]) == list
                for exception_tuple in analysis_results[5]:
                    assert type(exception_tuple) == tuple
                    assert len(exception_tuple) == 3
                    assert isinstance(exception_tuple[0], type)
                    assert isinstance(exception_tuple[1], Exception)
                    assert isinstance(exception_tuple[2], object)
                assert analysis_results[0] == test_case['tc_basic']['id']
            except AssertionError:
                self.api_error(
                    'Problem with the analyse of TC %s, wrong result received'
                    %
                    testcase_id
                )
                return

            # Only take the first
            verdict = OrderedDict()
            verdict['_type'] = 'verdict'
            verdict['verdict'] = analysis_results[1]
            verdict['description'] = analysis_results[3]
            verdict['review_frames'] = analysis_results[2]
            verdict['partial_verdicts'] = analysis_results[4]

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            # Prepare the result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True
            json_result['content'] = [
                token_res,
                test_case['tc_basic'],
                verdict
            ]
            self.log_message("Analysis response sent: " + str((analysis_results[4])))

            self.log_message("Analysis response sent: " + str(json.dumps(json_result)))

            # Here we will analyze the pcap file and get the results as json
            print(json.dumps(json_result))
            return



        # POST handler for the analyzer_allMightyAnalyze uri
        # It will allow users to analyze a pcap file without giving
        # a corresponding test case
        #
        # \param pcap_file => The pcap file that we want to analyze
        # \param token => The token previously provided
        # The pcap_file or the token is required, having both is also forbidden
        #
        elif self.path == '/api/v1/analyzer_allMightyAnalyze':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Not implemented for the moment
            self.api_error(
                "This method is not implemented yet, please come back later"
            )
            return

        # POST handler for the dissector_dissectFile uri
        # It will allow users to analyze a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to dissect
        # \param protocol_selection => The protocol name
        #
        elif self.path == '/api/v1/dissector_dissectFile':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            try:
                content_type = cgi.parse_header(self.headers['Content-Type'])
            except TypeError:
                self.api_error(
                    "Non empty POST datas and format of 'multipart/form-data' expected"
                )
                return

            # Check headers
            if any((
                len(content_type) == 0,
                content_type[0] is None,
                content_type[0] != 'multipart/form-data'
            )):
                self.api_error(
                    "POST format of 'multipart/form-data' expected, no file input 'pcap_file' found"
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type[0]
                })

            # Check the parameters passed
            if any((
                len(form) != 2,
                'pcap_file' not in form,
                'protocol_selection' not in form
            )):
                self.api_error(
                    'Expected POST=(pcap_file={file}, protocol_selection={text})'
                )
                return

            # Check the protocol_selection value
            protocol_selection = form.getvalue('protocol_selection')
            if not type(protocol_selection) == str:
                self.api_error('Expected protocol_selection post value to be a text (eq string)')
                return

            # In function of the protocol asked
            prot = get_protocol(protocol_selection)
            if prot is None:
                self.api_error('Unknown protocol %s' % protocol_selection)
                return

            # Generate a new token
            token = get_token()

            # Get the pcap file
            pcap_file = form.getvalue('pcap_file')

            # Path to save the file
            pcap_path = os.path.join(
                TMPDIR,
                token + '.dump'
            )

            # Write the pcap file to a temporary destination
            try:
                with open(pcap_path, 'wb') as f:
                    f.write(pcap_file)
            except:
                self.api_error("Couldn't write the temporary file")
                return

            # Prepare the result to return
            json_result = OrderedDict()
            json_result['_type'] = 'response'
            json_result['ok'] = True

            token_res = OrderedDict()
            token_res['_type'] = 'token'
            token_res['value'] = token

            # Get the dissection from dissector tool
            try:
                dissection = Dissector(pcap_path).dissect(eval(prot['name']))
            except TypeError as e:
                self.api_error('Dissector error: ' + str(e))
                return
            except pure_pcapy.PcapError:
                self.api_error(
                    "Expected 'pcap_file' to be a non empty pcap file"
                )
                return
            except:
                self.api_error(
                    "Couldn't read the temporary file %s and protocol is %s"
                    %
                    (
                        pcap_path,
                        prot['name']
                    )
                )
                return

            # Save the json dissection result into a file
            json_save = os.path.join(
                TMPDIR,
                token + '.json'
            )
            try:
                with open(json_save, 'w') as f:
                    json.dump(dissection, f)
            except:
                self.api_error("Couldn't write the json file")
                return

            # Add the token to the results
            dissection.insert(0, token_res)

            # The json result to return
            json_result['content'] = dissection

            # Here we will analyze the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # If we didn't manage to bind the request
        else:
            self.send_error(404)
            return


