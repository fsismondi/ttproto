#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_04 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_04
Objective:
Perform POST transaction (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.2,1.2,2.1,2.2,3.1

Pre-test
conditions:
•	Server accepts creation of new resource on / test (resource does not exist yet)

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a POST request with:
•	Type = 0(CON)
•	Code = 2(POST)
•	Content format  option
•	Empty or non-empty Payload

2
Check
The request sent by the client contains:
•	Type=0 and Code=2
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Verify
Server displays received information

4
Check
Server sends response containing:
•	Code = 65(2.01 Created)  or 68 (2.04 changed)
•	Message ID = CMID, Token = CTOK
•	Content-format option if payload non-empty
•	Zero or more Location-path options
•	Empty or non-empty Payload

5
Verify
Client displays the received response
"""
    def run (self):
        self.match_coap ("client", CoAP (type="con", code="post",
                        opt=self.uri ("/test")))
        self.match_coap ("client", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next()

        self.match_coap ("server", CoAP (
                        code = Any (65, 68),
                        mid = CMID,
                        tok = CTOK,
                ))
        if self.match_coap ("server", CoAP(pl = Not(b"")),None):
            self.match_coap ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")


