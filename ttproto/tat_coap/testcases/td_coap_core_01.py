#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_01 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_01
Objective:
Perform GET transaction (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1,1.2,2.1,2.2,3.1

Pre-test
conditions:
•	Server offers the resource /test with resource content is not empty that handles GET with an arbitrary payload

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a GET request with:
•	Type = 0(CON)
•	Code = 1(GET)

2
Check
The request sent by the client contains:
•	Type=0 and Code=1
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Code = 69(2.05 Content)
•	Message ID = CMID, Token = CTOK
•	Content-format option
•	Non-empty Paload

4
Verify
Client displays the received information
    """

    @classmethod
    @typecheck
    def stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        return [CoAP(type='con', code='get')]

    def run (self):
        self.match ("client", CoAP (type="con", code="get",
                        opt = self.uri ("/test")))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()

        if self.match ("server", CoAP (
                        code = 2.05,
                        mid = CMID,
                        tok =CTOK,
                        pl = Not(b""),
                    )):
            self.match ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                    ), "fail")
