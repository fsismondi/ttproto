#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_31 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_31
Objective:
Perform CoAP Ping (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 4.3

Pre-test
conditions:
(Should work with any CoAP server)

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a "Ping" request with:
•	Type = 0 (CON)
•	Code = 0 (empty)

2
Check
The request sent by the client is four bytes and contains:
•	Type=0 and Code=0
•	Client-generated Message ID (➔ CMID)
•	Zero-length Token
•	No payload

3
Check
Server sends four-byte RST response containing:
•	Type=3 and Code=0
•	Message ID = CMID
•	Zero-length Token
•	No payload

4
Verify 	Client displays that the "Ping" was successful
    """

    def run (self):
        self.match_coap ("client", CoAP (type="con", code = 0,tok=b"",pl=b""))
        CMID = self.frame.coap["mid"]

        self.next_skip_ack()

        if self.match_coap ("server", CoAP (type=3)):
            self.match_coap ("server", CoAP (
                        code=0,
                        tok=b"",
                        pl=b"",
                    ), "fail")

