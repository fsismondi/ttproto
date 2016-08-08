#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_18 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_18
Objective:
Perform POST transaction with responses containing several Location-Path options
(CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1,5.10.8,5.9.1.1

Pre-test
conditions:
•	Server accepts creation of new resource on  /testand the created resource is
located at  /location1/location2/location3 (resource does not exist yet)

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable POST request to
server’s resource


2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 2 (POST)
•	An arbitrary payload
•	Content-format option
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Code = 65 (2.01 created)
and three options of type Location-Path, with the values (none of which contains a "/"):
•	location1
•	location2
•	location3



4
Verify
Client displays the response
"""

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='con', code='post')
        ]

    request_uri = "/test"

    def run (self):
        self.match ("client", CoAP (type="con", code = "post",pl=Not(b""),
                    opt=self.uri(
                        self.request_uri,
                        CoAPOptionContentFormat(),
                    )))

        self.next_skip_ack()

        self.match ("server", CoAP (code=2.01,
                        opt=Opt(
                            CoAPOptionLocationPath ("location1"),
                            CoAPOptionLocationPath ("location2"),
                            CoAPOptionLocationPath ("location3"),
                )))

        self.next_skip_ack (optional = True)
