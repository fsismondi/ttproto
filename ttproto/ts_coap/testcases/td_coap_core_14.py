#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *

class TD_COAP_CORE_14 (CoAPTestcase):
    """Identifier:
TD_COAP_CORE_14
Objective:
Perform GET transaction containing several URI-Query options (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.4.5, 5.10.2,6.5

Pre-test
conditions:
•	Server offers a /query resource with resource content is not empty

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable GET request with three Query parameters (e.g. ?first=1&second=2&third=3) to the server’s resource

2
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "query"
and two options of Uri-Query, with values such as:
•	first=1
•	second=2


3
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID, Token = CTOK
•	Content-format option
•	Non-empty Payload

4
Verify
Client displays the response

"""
    def run (self):
        if self.urifilter:
            uri_query_opt = self.uri ("/query?first=1&second=2")
        else:
            uri_query_opt = Opt(CoAPOptionUriQuery(), superset=True)

        self.match_coap ("client", CoAP (code = "get",
                        type = "con",
                        opt = uri_query_opt))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        opts = list (filter ((lambda o: isinstance (o, CoAPOptionUriQuery)), self.frame.coap["opt"]))

        if len (opts) < 2:
            self.setverdict ("inconclusive", "expect multiple UriQuery options")

        self.next_skip_ack()

        self.match_coap ("server", CoAP (	code = 2.05,
                            mid=CMID,
                            tok=CTOK,
                            pl = Not (b""),
                            opt = Opt (CoAPOptionContentFormat()),
                ))

