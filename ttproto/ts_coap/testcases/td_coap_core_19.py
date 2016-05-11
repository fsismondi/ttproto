#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_19(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_19
Objective:
Perform POST transaction with responses containing several Location-Query options
(CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1,5.10.8,5.9.1.1

Pre-test
conditions:
•	Server accepts creation of new resource on uri  /location-query, the location of
the created resource contains two query parameters ?first=1&second=2

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable POST request to
server’s resource


2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 2 (POST)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Content-format option
•	Empty or non-empty Payload
•	Uri-Path option "location-query"

3
Check
Server sends response containing:
•	Code = 65 (2.01 created)
•	Message ID = CMID, Token = CTOK
•	Content-format option if payload non-empty
•	Zero or more Location-path options
•	Empty or non-empty Payload

and two options of type Location-Query, with the values (none of which contains a "?" or "&"):

•	first=1
•	second=2


4
Verify
Client displays the response
"""

    def run(self):
        self.match_coap("client", CoAP(type="con", code="post",
                                       opt=self.uri(
                                           "/location-query",
                                           CoAPOptionContentFormat(),
                                       )))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next_skip_ack()

        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=2.01,
                                       mid=CMID,
                                       tok=CTOK,
                                       opt=Opt(
                                           CoAPOptionLocationQuery("first=1"),
                                           CoAPOptionLocationQuery("second=2"),
                                       )))
        if self.match_coap("server", CoAP(pl=Not(b"")), None):
            self.match_coap("server", CoAP(
                opt=Opt(CoAPOptionContentFormat()),
            ), "fail")
        self.next_skip_ack(optional=True)
