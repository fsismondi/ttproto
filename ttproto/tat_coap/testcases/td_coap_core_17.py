#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_17 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_17
Objective:
Perform GET transaction with a separate response (NON mode)
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
Client is requested to send a non-confirmable GET request to server’s resource

2
Check
The request sent by the client contains:
•	Type = 1 (NON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Uri-Path option "separate"

3
Check
Server DOES NOT send response containing:
•	Type = 2 (ACK)
•	Same message ID as in the request in step 2
•	empty Payload


4
Check
Server sends response containing:
•	Type  = 1 (NON)
•	Code = 69 (2.05 content)
•	Server-generated Message ID (➔ SMID)
•	Content-format option
•	Non-empty Payload

5
Verify
Client displays the response
"""
    def run (self):
        self.match ("client", CoAP (type="non", code = "get",
                    opt=self.uri("/separate")))

        self.next()

        #FIXME: may be out-of-order
        if self.get_coap_layer() in CoAP (type="ack"):
            self.set_verdict ("fail", "server must no send any ack")
            self.next()

        if self.match ("server", CoAP (type="non", code=2.05)):
            self.match ("server", CoAP (
                        pl = Not (b''),
                        opt= Opt(CoAPOptionContentFormat())
                ), "fail")


