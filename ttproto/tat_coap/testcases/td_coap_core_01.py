#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *

class TD_COAP_CORE_01 (CoAPTestcase):
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

    def run (self):
        self.match_coap ("client", CoAP (type="con", code="get",
                        opt = self.uri ("/test")))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next()

        if self.match_coap ("server", CoAP (
                        code = 2.05,
                        mid = CMID,
                        tok =CTOK,
                        pl = Not(b""),
                    )):
            self.match_coap ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                    ), "fail")


