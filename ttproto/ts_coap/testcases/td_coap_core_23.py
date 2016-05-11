#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_23(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_23
Objective:
Perform PUT transaction containing the If-None-Match option (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1, 5.10.7,5.10.10,12.1.12

Pre-test
conditions:
•	Server should offer a /create1 resource, which does not exist and which can be created by the client
•	Client & server supports If-Non-Match


Test Sequence:
Step
Type
Description

Part A: single creation

1
Stimulus
Client is requested to send a confirmable PUT request to
server’s resource so as to atomically create the resource.

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Content-format option
•	Uri-Path option "create1"
•	Option Type=If-None-Match
•	An arbitrary payload

3
Check
Server sends response containing:
•	Code = 65 (2.01 Created)
•	Message ID = CMID, Token = CTOK
•	Content-format option if payload non-empty
•	Empty or non-empty Payload


4
Verify
Client displays the response and the server created a new resource

Part B: concurrent creations

5
Stimulus
Client is requested to send a confirmable PUT request to
server’s resource so as to atomically create the resource.

6
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Another client-generated Message ID ≠ CMID (➔ CMID2)
•	Client-generated Token which may or may not be ≠ CTOK (➔ CTOK2)
•	Content-format option
•	Uri-Path option "create1"
•	Option Type=If-None-Match
•	An arbitrary payload

7
Check
Server sends response containing:
•	140 (4.12 Precondition Failed)
•	Message ID = CMID2, Token = CTOK2
•	Optional Content-format option
•	Empty or non-empty Payload


8
Verify
Client displays the response
"""
    request_uri = "/create1"

    def run(self):
        # Part A

        self.match_coap("client", CoAP(type="con", code="put",
                                       opt=Opt(
                                           CoAPOptionContentFormat(),
                                           CoAPOptionUriPath(self.request_uri[1:]),
                                           CoAPOptionIfNoneMatch(),
                                       ),
                                       pl=Not(b"")))

        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next_skip_ack()

        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.01, mid=CMID, tok=CTOK)):
            raise self.Stop()
        if self.match_coap("server", CoAP(pl=Not(b"")), None):
            self.match_coap("server", CoAP(
                opt=Opt(CoAPOptionContentFormat()),
            ), "fail")
        self.next_skip_ack(optional=True)

        # Part B
        self.chain()

        self.match_coap("client", CoAP(type="con", code="put",
                                       opt=Opt(
                                           CoAPOptionContentFormat(),
                                           CoAPOptionUriPath(self.request_uri[1:]),
                                           CoAPOptionIfNoneMatch(),
                                       ),
                                       pl=Not(b"")))
        CMID2 = self.frame.coap["mid"]
        CTOK2 = self.frame.coap["tok"]
        if CMID2 is Not(b''):
            if CMID2 == CMID:
                self.setverdict("fail", "Message ID should be different")
        if CTOK2 is Not(b''):
            if CTOK2 == CTOK:
                self.setverdict("fail", "Token should be different")

        self.next_skip_ack()

        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=4.12,
                                              mid=CMID2,
                                              tok=CTOK2,
                                              pl=b"")):
            raise self.Stop()

        self.next_skip_ack(optional=True)
