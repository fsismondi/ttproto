#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_12(CoAPTestCase):
    """Identifier:
TD_COAP_CORE_12
Objective:
Perform GET transaction using empty Token (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 2.2 ,5.8.1, 5.10.1

Pre-test
conditions:
•	Server offers the resource /test with resource content is not empty that handles GET with an arbitrary payload

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable GET request using zero-length Token to server’s resource

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Zero-Length Token ➔ CTOK
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID, Token = CTOK
•	Not empty Payload
•	Content format option

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
        """
        return [
            CoAP(type='con', code='get', tok=b'')
        ]

    def run(self):
        self.match("client", CoAP(type="con", code="get",
                                       tok=b"",
                                       opt=self.uri("/test")))

        self.next_skip_ack()

        if self.match("server", CoAP(code=2.05,
                                          pl=Not(b""),
                                          opt=Opt(CoAPOptionContentFormat()),
                                          )):
            self.match("server", CoAP(tok=b""), "fail")
