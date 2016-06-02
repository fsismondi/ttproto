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
import time
import errno
import signal
from urllib.parse import urlparse, parse_qs


DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

API_URL = 'http://127.0.0.1:2080'
API_SNIFFER = 'http://127.0.0.1:5000'
CURRENT_TESTCASE = "TEST"
TEMP_DIR = "./data/coordinator/dumps"
TEST_CASES = []


class RequestHandler(http.server.BaseHTTPRequestHandler):

    def coord_error(self, message):
        """
            Function for generating a json error
        """
        self.log_message("%s error: %s", self.path, message)
        print(json.dumps({
            '_type': 'response',
            'ok': False,
            'error': message
        }))

    def log_message(self, format, *args, append=""):
        global log_file
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
        log_file.write(txt)
        log_file.flush()

    def do_GET(self):

        # Get the url and parse it
        url = urlparse(self.path)

        # The global variable
        global TEST_CASES

        # #################### GUI part ####################

        # GET handler for the gui web page
        #
        if url.path == '/':

            # Just open and provide the file
            try:
                fp = open('drafts/finterop-gui/finterop.html', 'rb')
            except FileNotFoundError:
                self.log_message('Finterop html file not found')
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            self.wfile.write(fp.read())
            return

        # GET handler for the gui asserts
        #
        elif url.path[:8] == '/js-libs':

            # Just open and provide the file
            try:
                fp = open('drafts/finterop-gui' + url.path, 'rb')
            except FileNotFoundError:
                self.log_message("Assert file %s not found", url.path)
                self.send_error(404)
                return

            # In function of the type
            if url.path[-2:] == 'js':
                content_type = 'application/javascript'
            elif url.path[-3:] == 'css':
                content_type = 'text/css'
            else:
                content_type = 'text/html'

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()

            self.wfile.write(fp.read())
            return

        # #################### End of GUI part ####################

        # GET handler for the get_testcases uri
        # It will give to the finterop client the list of the test cases
        #
        elif url.path == '/finterop/get_testcases':

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Send the header
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()

            # Launch the post request on ttproto api
            try:
                resp = requests.get(API_URL + '/api/v1/testcase_getList')
                if resp.status_code != requests.codes.ok:
                    raise
            except:
                self.coord_error(
                    'ERROR: No test cases found, maybe the API isn\'t up yet'
                )
                return

            # Store the test cases into a variable
            TEST_CASES = resp.json()

            # Just forward the json
            print(json.dumps(TEST_CASES))
            return

        # GET handler for the start_test_suite uri
        # It will begin the test suite process
        #
        elif url.path == '/finterop/start_test_suite':

            #
            # HERE YOU PUT THE FUNCTIONS THAT YOU NEED TO START THE TEST SUITE
            #

            # Get the first test case
            first_tc = TEST_CASES['content'][0]
            self.log_message(
                "Test suite launched with first tc as %s",
                first_tc['id']
            )

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

        # If unknown request
        else:
            self.send_error(404)
            return

    def do_POST(self):

        # The job counter
        global job_id
        global CURRENT_TESTCASE
        global TEMP_DIR
        global API_SNIFFER
        job_id += 1

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
                self.coord_error('Expected POST=(testcase_id)')
                return

            # Get the test case id
            testcase_id = form.getvalue('testcase_id')

            # Check that the test case is contained into the available ones
            valid_testcase = False
            for tc in TEST_CASES['content']:
                if tc['id'] == testcase_id:
                    valid_testcase = True
                    break

            # If not valid test case
            if not valid_testcase:
                self.coord_error('Test case not found')
                return

            # Start the sniffer

            CURRENT_TESTCASE = testcase_id

            par = {'testcase_id': testcase_id}
            url = API_SNIFFER + "/sniffer_api/launchSniffer"
            try:
                r = requests.post(url, params=par)
            except:
                self.coord_error(
                    'Sniffer API dosen\'t respond, maybe it isn\'t up yet'
                )
                return
            # TODO log(r.content)

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

        # POST handler for the finish_test_case uri
        # It will allow users to end a test case
        #
        # \param testcase_id => The TC that we want to end
        #
        elif self.path == '/finterop/finish_test_case':

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
                self.coord_error('Expected POST=(testcase_id)')
                return

            # Get the test case id
            testcase_id = form.getvalue('testcase_id')

            # Check that the test case is contained into the available ones
            valid_testcase = False
            for tc in TEST_CASES['content']:
                if tc['id'] == testcase_id:
                    valid_testcase = True
                    next_test_case = (TEST_CASES['content'].index(tc) + 1)
                    break

            # If not valid test case
            if not valid_testcase:
                self.coord_error('Test case not found')
                return

            #
            # HERE YOU PUT THE FUNCTIONS THAT YOU NEED TO STOP THE TEST CASE
            # ASSOCIATED WITH THIS TEST CASE ID
            #
            # Kill the sniffer
            # Get the pcap file
            # Analyse it and return the result

            # TODO useful for other API calls?
            def getPcapFromApiSniffer(api_sniffer: str, route: str, testcase_id, save_dir: str):

                par = {'testcase_id': testcase_id}
                r = requests.get(api_sniffer + route, params=par)
                attachment_data = r.content
                # save to file
                try:
                    with open(save_dir + testcase_id + ".pcap", 'wb') as f:
                        f.write(attachment_data)
                    self.log_message(
                        "Pcap correctly save at %s for tc %s from sniffer %s",
                        save_dir,
                        testcase_id,
                        api_sniffer + route
                    )
                except:
                    self.log_message(
                        "Didn't manage to save pcap at %s for tc %s from sniffer %s",
                        save_dir,
                        testcase_id,
                        api_sniffer + route
                    )

            # finish sniffer
            url = API_SNIFFER + "/sniffer_api/finishSniffer"

            try:
                r = requests.post(url)
                self.log_message("Call to %s done", url)
            except:
                self.coord_error(
                    'Sniffer API dosen\'t respond, maybe it isn\'t up yet'
                )
                return

            # tologger(r.content)
            self.log_message(
                "Content of the response on %s call is %s",
                url,
                r.content.json()
            )

            # get PCAP from sniffer, and put it in TEMP_DIR
            getPcapFromApiSniffer(API_SNIFFER, "/sniffer_api/getPcap", CURRENT_TESTCASE, TEMP_DIR)

            # forwards PCAP to TAT API
            url = API_URL + "/api/v1/testcase_analyse"
            par = {'testcase_id': CURRENT_TESTCASE}
            fileToPost = {'file': open(TEMP_DIR, 'rb')}

            try:
                r = requests.post(url, files=fileToPost, params=par)
                self.log_message("Call to %s done", url)
            except:
                self.coord_error(
                    'Sniffer API dosen\'t respond, maybe it isn\'t up yet'
                )
                return

            # TODO log
            self.log_message(
                "Content of the response on %s call is %s",
                url,
                r.json()
            )

            # TODO put r.json into the json_result
            # Prepare the result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'message',
                        'message': 'Test case ' + testcase_id + ' correctly finished'
                    },
                    {
                        '_type': 'information',
                        'last_test_case': (next_test_case == len(TEST_CASES['content']))
                    },
                    TEST_CASES['content'][next_test_case],  # The next test case
                    {
                        '_type': 'verdict',
                        'verdict': 'inconc',
                        'description': testcase_id,
                        'review_frames': []
                    }
                ]
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


def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "coord-webserver.log"), "a")

    # ttproto API part
    cgitb.enable(display=0, logdir=LOGDIR)
