#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_06 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_06
Objective:
Perform DELETE transaction (NON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP]  5.8.4,5.2.3

Pre-test
conditions:
•	Server offers a /test resource that handles DELETE

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a DELETE request with:
•	Type = 1(NON)
•	Code = 4(DELETE)

2
Check
The request sent by the client contains:
•	Type=1 and Code=4
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Type = 1(NON)
•	Code = 66(2.02 Deleted)
•	Server-generated Message ID (➔ SMID)
•	Token = CTOK
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

4
Verify
Client displays the received information
"""
    def run (self):
        self.match ("client", CoAP (type="non", code="delete",
                        opt = self.uri ("/test")))

        CTOK = self.get_coap_layer()["tok"]

        self.next()

        self.match ("server", CoAP (type="non", code = 2.02,tok=CTOK))
        if self.match ("server", CoAP(pl = Not(b"")),None):
            self.match ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")


