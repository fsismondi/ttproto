#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_13 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_13
Objective:
Perform GET transaction containing several URI-Path options (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.4.5, 5.10.2,6.5

Pre-test
conditions:
•	Server offers a /seg1/seg2/seg3 resource with resource content is not empty

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable GET request to server’s resource

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

and three options of type Uri-Path, with the values:

•	seg1
•	seg2
•	seg3


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
            CoAP(type='con', code='get')
        ]

    def run (self):
        if self.urifilter:
            uri_path_opt = self.uri ("/seg1/seg2/seg3")
        else:
            uri_path_opt = Opt(CoAPOptionUriPath(), superset=True)

        self.match ("client", CoAP (code = "get",
                        type = "con",
                        opt = uri_path_opt))

        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        opts = list (filter ((lambda o: isinstance (o, CoAPOptionUriPath)), self.coap["opt"]))

        if len (opts) > 1:
            self.set_verdict ("pass", "multiple UriPath options")
        else:
            self.set_verdict ("inconc", "only one UriPath option")

        # TODO: move this checks outside the testcases
        for o in opts:
            if "/" in str (o["val"]):
                self.set_verdict ("fail", "option %s contains a '/'" % repr (o))

        self.next_skip_ack()

        self.match ("server", CoAP (	code = 2.05,
                            type = Any (CoAPType("con"), "ack"),
                            mid=CMID,
                            tok=CTOK,
                            pl = Not (b""),
                            opt = Opt (CoAPOptionContentFormat()),
                ))


