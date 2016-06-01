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

        # #################### End of Coordinator part ##################### #

    def do_POST(self):

        # The job counter
        global job_id
        job_id += 1

        # ########################## ttproto API ########################### #

        # POST handler for the testcase_analyse uri
        # It will allow users to analyse a pcap file corresponding to a TC
        #
        # \param pcap_file => The pcap file that we want to analyse
        # \param testcase_id => The id of the corresponding test case
        # \param token => The token previously provided
        # The pcap_file or the token is required, having both is also forbidden
        #
        if self.path == '/api/v1/testcase_analyse':

            # Send the header
            self.send_response(200)
            self.send_header('Content-Type', 'application/json;charset=utf-8')
            self.end_headers()

            # Bind the stdout to the http output
            os.dup2(self.wfile.fileno(), sys.stdout.fileno())

            # Get the content type
            content_type = cgi.parse_header(self.headers['Content-Type'])
            content_type = content_type[0]

            # Check headers
            if any((
                content_type is None,
                content_type != 'multipart/form-data'
            )):
                api_error(
                    'POST format of \'multipart/form-data\' expected'
                )
                return

            # Get post values
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                keep_blank_values=True,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type
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
                api_error(
                    'Expected POST=([pcap_file|token], testcase_id)'
                )
                return

            # Get the pcap file
            pcap_file = form.getvalue('pcap_file')
            if (pcap_file):

                # Path to save the file
                timestamp = time.strftime("%y%m%d_%H%M%S")
                pcap_path = os.path.join(
                    TMPDIR,
                    "%s_%04d.dump" % (timestamp, job_id)
                )

                # Write the pcap file to a temporary destination
                with open(pcap_path, 'wb') as f:
                    f.write(pcap_file)

            # Get the token
            token = form.getvalue('token')

            # Generate the token if none given
            if not token:
                token = hashlib.sha1(
                    str.encode((
                        "%s%s%04d%s" %
                        (
                            HASH_PREFIX,
                            timestamp,
                            job_id,
                            HASH_SUFFIX
                        )
                    ), encoding='utf-8')
                )
                token = base64.urlsafe_b64encode(token.digest()).decode()

            # Get the test case and its informations
            testcase_id = form.getvalue('testcase_id')
            try:
                test_case = analysis.get_implemented_testcases(testcase_id)
            except FileNotFoundError:
                api_error(
                    'No test case with the id %s' % testcase_id
                )
                return

            # FIXME: Don't forget to remove this block when the bug is fixed
            except ImportError:
                os.chdir('../../..')
                api_error(
                    'TC %s found but a bug is to fix' % testcase_id
                )
                return

            if (len(test_case) != 1):
                api_error(
                    'TC %s is not unique' % testcase_id
                )
                return

            # Prepare the result to return
            json_result = {
                '_type': 'response',
                'ok': True,
                'content': [
                    {
                        '_type': 'token',
                        'value': token
                    },
                    {
                        '_type': 'tc_basic',
                        'id': test_case[0][0],
                        'objective': test_case[0][1]
                    },
                    {
                        '_type': 'verdict',
                        'verdict': '',
                        'description': '',
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