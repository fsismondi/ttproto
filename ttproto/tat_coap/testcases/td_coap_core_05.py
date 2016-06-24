#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_05 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_05
Objective:
Perform GET transaction (NON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP]  5.8.1, 5.2.3

Pre-test
conditions:
•	Server offers a /test resource with resource content is not empty that handles GET

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a GET request with:
•	Type = 1(NON)
•	Code = 1(GET)

2
Check
The request sent by the client contains:
•	Type=1 and Code=1
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Type = 1(NON)
•	Code= 69(2.05 Content)
•	Server-generated Message ID (➔ SMID)
•	Token = CTOK
•	Content-format option

4
Verify
Client displays the received information
"""
    def run (self):
        self.match_coap ("client", CoAP (type="non", code="get",
                        opt = self.uri ("/test")))
        CTOK = self.frame.coap["tok"]

        self.next()

        if self.match_coap ("server", CoAP (
                        type = "non",
                        code = 2.05,
                        tok = CTOK,
                )):
            self.match_coap ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat())
                ), "fail")


