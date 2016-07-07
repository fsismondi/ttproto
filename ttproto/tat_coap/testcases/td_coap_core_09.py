#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_09 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_09
Objective:
Perform GET transaction with separate response (CON mode, no piggyback)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] clause  5.8.1,5.2.2

Pre-test
conditions:
•	 Server offers a resource /separate which is not served immediately and which therefore is not acknowledged in a piggybacked way.
cannot be acknowledged in a piggybacked way.

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable GET request to server’s resource

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Uri-Path option "separate"
•	Client-generated Token (➔ CTOK)


3
Check
Server sends response containing:
•	Type = 2 (ACK)
•	Code = 0
•	Message ID = CMID
•	empty Payload

4
Check
Server sends response containing:
•	Type  = 0 (CON)
•	Code = 69 (2.05 content)
•	Server-generated Message ID (➔ SMID)
•	Token = CTOK
•	Content-format option
•	Non-empty Payload

5
Check
Client sends response containing:
•	Type = 2 (ACK)
•	Code = 0
•	Message ID = SMID
•	empty Payload

6
Verify
Client displays the response
Note: Steps 3 and 4 may occur out-of-order
"""
    def run(self):
        self.match ("client", CoAP (type="con", code = "get",
                        opt = self.uri ("/separate")))
        CMID = self.get_coap_layer()["mid"]
        CTOK = self.get_coap_layer()["tok"]

        self.next()

        #FIXME: may be out-of-order
        if not self.match	("server", CoAP (type="ack", code=0, mid=CMID, pl = b"")):
            raise self.Stop()

        self.next()

         # FIXME: this is in a different conversation
        self.match ("server", CoAP (type="con", code=2.05))
        self.match ("server", CoAP (
                        tok=CTOK,
                        pl = Not (b''),
                        opt= Opt(CoAPOptionContentFormat())
                ), "fail")
        SMID = self.get_coap_layer()["mid"]

        self.next()

        self.match ("client", CoAP (type="ack", code=0, mid=SMID,pl=b""))


