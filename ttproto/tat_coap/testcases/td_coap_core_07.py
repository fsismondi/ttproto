#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_07 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_07
Objective:
Perform PUT transaction (NON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.3, 5.2.3

Pre-test
conditions:
•	Server offers a /test resource that handles PUT

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a PUT request with:
•	Type = 1(NON)
•	Code = 3(PUT)
•	An arbitrary payload
•	Content-format option

2
Check
The request sent by the client contains:
•	Type=1 and Code=3
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Verify
Server displays the received information

4
Check
Server sends response containing:
•	Type = 1(NON)
•	Code = 68 (2.04 Changed) or 65 (2.01 Created)
•	Server-generated Message ID (➔ SMID)
•	Token = CTOK
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

5
Verify
Client displays the received response
"""
    def run (self):
        self.match ("client", CoAP (type="non", code="put",
                        opt = self.uri ("/test")))
        self.match ("client", CoAP (
                        pl  = Not (b''),
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")
        CTOK = self.get_coap_layer()["tok"]

        self.next()

        self.match ("server", CoAP (
                        type = "non",
                        code = Any (65, 68),
                        tok = CTOK,
                ))
        if self.match ("server", CoAP(pl = Not(b"")),None):
            self.match ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")


