#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_11 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_11
Objective:
Perform GET transaction containing non-empty Token with a separate response (CON mode)

Configuration:
CoAP_CFG_BASIC
References:
[COAP] 2.2, 5.2.2,  5.8.1

Pre-test
conditions:
•	Server offers a resource /separate which is not served immediately and which therefore is not acknowledged in a piggybacked way.

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a GET request to server’s
resource including Token option

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Length of the token should be between 1 to 8 Bytes
•	Uri-Path option "separate"

3
Check
Server sends acknowledgement containing:
•	Type = 2 (ACK)
•	Code = 0 (Empty)
•	Message ID = CMID
•	empty Payload


4
Check
Server sends response containing:
•	Type  = 0 (CON)
•	Code = 69 (2.05 content)
•	Server-generated Message ID (➔ SMID)
•	Token = CTOK
•	Non-empty Payload

5
Check
Client sends acknowledgement containing:
•	Type = 2 (ACK)
•	Code = 0 (Empty)
•	Message ID = SMID
•	Empty Payload


6
Verify
Client displays the response
"""

    def run (self):
        self.match_coap ("client", CoAP (	type="con",
                            code = "get",
                            tok = Not (b""),
                            opt = self.uri ("/separate"),
                ))
        self.match_coap ("client", CoAP (tok = Length (bytes, (1, 8))
                ), "fail")
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next()

        # FIXME: may be out-of-order
        if not self.match_coap	("server", CoAP (type="ack", code=0, mid=CMID,pl=b"")):
            raise self.Stop()

        self.next()

         # FIXME: this is in a different conversation
        self.match_coap ("server", CoAP (type="con", code=2.05))
        self.match_coap ("server", CoAP (
                        pl = Not (b''),
                        tok= CTOK,
                        )
                , "fail")
        SMID = self.frame.coap["mid"]

        self.next()

        self.match_coap ("client", CoAP (type="ack", code=0, mid=SMID,pl=b""))


