#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_20(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_20
Objective:
Perform GET transaction containing the Accept option (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] clause 5.8.1,5.10.5,5.10.4

Pre-test
conditions:
•	Server should provide a resource /multi-format which exists in two formats:
-	text/plain;charset=utf-8
-	application/xml

Test Sequence:
Step
Type
Description

Part A: client requests a resource in text format


1
Stimulus
Client is requested to send a confirmable GET request to
server’s resource


2
Check
The request sent request by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Option type = Accept, value = 0 (text/plain;charset=utf-8)
•	Uri-Path option "multi-format"

3
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID, Token = CTOK
•	Option type = Content-Format, value = 0 (text/plain;charset=utf-8)
•	Payload = Content of the requested resource in text/plain;charset=utf-8 format

4
Verify
Client displays the response

Part B: client requests a resource in xml format

5
Stimulus
Client is requested to send a confirmable GET request to
server’s resource


6
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Another client-generated Message ID ≠ CMID (➔ CMID2)
•	Client-generated Token which may or may not be ≠ CTOK (➔ CTOK2)
•	Option type = Accept, value = 41 (application/xml)

7
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID2, Token = CTOK2
•	Option type = Content-Format, value = 41 (application/xml)
Payload = Content of the requested resource in application/xml format

8
Verify
Client displays the response
"""

    def run(self):
        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=self.uri("/multi-format") if self.urifilter else Opt(CoAPOptionAccept())))
        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=Opt(CoAPOptionAccept(0))))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next_skip_ack()

        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=2.05,
                                       mid=CMID,
                                       tok=CTOK,
                                       opt=Opt(CoAPOptionContentFormat(0)),
                                       pl=Not(b"")))

        self.next_skip_ack(optional=True)

        self.chain()

        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=self.uri("/multi-format", CoAPOptionAccept(41))))
        CMID2 = self.frame.coap["mid"]
        CTOK2 = self.frame.coap["tok"]
        if CMID2 is Not(b''):
            if CMID2 == CMID:
                self.setverdict("fail", "Message ID should be different")
        if CTOK2 is Not(b''):
            if CTOK2 == CTOK:
                self.setverdict("fail", "Token should be different")

        self.next_skip_ack()

        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=2.05,
                                       mid=CMID2,
                                       tok=CTOK2,
                                       opt=Opt(CoAPOptionContentFormat(41)),
                                       pl=Not(b"")))

        self.next_skip_ack(optional=True)
