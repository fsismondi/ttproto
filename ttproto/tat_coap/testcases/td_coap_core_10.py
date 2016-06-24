#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_10 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_10
Objective:
Perform GET transaction containing non-empty Token (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] clause 2.2 ,5.8.1, 5.10.1

Pre-test
conditions:
•	Server offers a /test resource with resource content is not empty that handles GET

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a GET request to server’s resource including Token option

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Option Type = Token
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Length of the token should be between 1 to 8 Bytes
•	Uri-Path option "test"


3
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID, Token = CTOK
•	Content-format option
•	Non-empty Payload

4
Verify
Client displays the response
"""
    def run (self):
        self.match_coap ("client", CoAP (	code = "get",
                            type = "con",
                            tok = Not (b""),
                            opt = self.uri ("/test")
        ))
        self.match_coap ("client", CoAP (tok = Length (bytes, (1, 8))
                ), "fail")
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next()

        if self.match_coap ("server", CoAP (	code = 2.05,
                            pl  = Not (b"")
                )):
            self.match_coap ("server", CoAP (mid= CMID,tok = CTOK,opt= Opt(CoAPOptionContentFormat())), "fail")


