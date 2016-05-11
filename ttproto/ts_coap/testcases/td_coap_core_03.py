 #!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *

class TD_COAP_CORE_03 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_03
Objective:
Perform PUT transaction (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.3,1.2,2.1,2.2,3.1

Pre-test
conditions:
•	Server offers already available resource /test  or accepts creation of new resource on /test  that handles PUT

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a PUT request with:
•	Type = 0(CON)
•	Code = 3(PUT)
•	Content-format  option
•	Empty or non-empty Payload

2
Check
The request sent by the client contains:
•	Type=0 and Code=3
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Verify
Server displays received information

4
Check
Server sends response containing:
•	Code = 68 (2.04 Changed) or 65 (2.01 Created)
•	Message ID = CMID, Token = CTOK
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

5
Verify
Client displays the received response
"""
    def run (self):
        self.match_coap ("client", CoAP (type="con", code="put",
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


