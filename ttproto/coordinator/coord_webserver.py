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
import sys
import os
import cgi
import cgitb
import json
import hashlib
import base64
import requests
from urllib.parse import urlparse, parse_qs

API_URL = 'http://127.0.0.1:2080'


def cord_error(message):
    """
        Function for generating a json error
    """
    print(json.dumps({
        '_type': 'response',
        'ok': False,
        'error': message
    }))


class RequestHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):

        # Get the url and parse it
        url = urlparse(self.path)

        # ######################## Coordinator part ######################### #

        # GET handler for the get_testcases uri
        # It will give to the finterop client the list of the test cases
        #
        if url.path == '/finterop/get_testcases':

            # Launch the post request on ttproto api
            resp = requests.get(API_URL + '/api/v1/testcase_getList')

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Just forward the json
            print(json.dumps(resp.json()))
            return

        # GET handler for the start_test_suite uri
        # It will begin the test suite process
        #
        elif url.path == '/finterop/start_test_suite':

            #
            # HERE YOU PUT THE FUNCTIONS THAT YOU NEED TO START THE TEST SUITE
            #

            # Launch the post request on ttproto api
            resp = requests.get(API_URL + '/api/v1/testcase_getList')

            # Get the first test case
            tcs = resp.json()
            first_tc = tcs['content'][0]

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Just forward the json
            print(json.dumps(
                {
                    '_type': 'response',
                    'ok': True,
                    'content': [
                        first_tc,
                        {
                            '_type': 'message',
                            'message': 'Start test case ' + first_tc['id'] + ' when ready'
                        }
                    ]
                }
            ))
            return

        # #################### End of Coordinator part ##################### #

    def do_POST(self):

        # The job counter
        global job_id
        job_id += 1

        # ########################## ttproto API ########################### #

        # POST handler for the start_test_case uri
        # It will allow users to begin a TC
        #
        # \param testcase_id => The TC that we want to launch
        #
        if self.path == '/finterop/start_test_case':

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                keep_blank_values=True,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers['Content-Type']
                })

            # Check that we have the two values
            if any((
                len(form) != 1,
                'testcase_id' not in form
            )):
                cord_error('Expected POST=(testcase_id)')
                return

            # Get the test case id
            testcase_id = form.getvalue('testcase_id')

            # Launch the post request on ttproto api
            resp = requests.get(API_URL + '/api/v1/testcase_getList')
            test_cases = resp.json()

            # Check that the test case is contained into the available ones
            valid_testcase = False
            for tc in test_cases['content']:
                if tc['id'] == testcase_id:
                    valid_testcase = True
                    break

            # If not valid test case
            if not valid_testcase:
                cord_error('Test case not found')
                return

            #
            # HERE YOU PUT THE FUNCTIONS THAT YOU NEED TO START THE TEST CASE
            # ASSOCIATED WITH THIS TEST CASE ID
            #

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Prepare the result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'message',
                        'message': 'Test case ' + testcase_id + ' started, press the Finish button when completed'
                    }
                ]
            }

            # Here we will analyse the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # POST handler for the testcase_analyse uri
        # It will allow users to analyse a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to analyse
        # \param testcase_id => The id of the corresponding test case
        # \param token => The token previously provided
        # The pcap_file or the token is required, having both is also forbidden
        #
        elif self.path == '/api/v1/testcase_analyse':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # TODO

            # Prepare the result to return
            json_result = {
            }

            # Here we will analyse the pcap file and get the results as json
            print(json.dumps(json_result))
            return

        # If we didn't manage to bind the request
        else:
            self.send_error(404)
            return

job_id = 0


__shutdown = False


def shutdown():
    global __shutdown
    __shutdown = True
