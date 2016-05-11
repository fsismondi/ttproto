#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_21(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_21
Objective:
Perform GET transaction containing the ETag option (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1, 5.10.7,5.10.10,12.1.12

Pre-test
conditions:
•	Server should offer a /validate resource which vary in time
•	Client & server supports ETag option
•	The Client‘s cache must be purged

Test Sequence:
Step
Type
Description

Part A: Verifying that client cache is empty

1
Stimulus
Client is requested to send a confirmable GET request to server’s resource


2
Check
The request sent request by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "validate"
•	No ETag option

3
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID, Token = CTOK
•	Option type = ETag, value = a value chosen by the server (➔ ETAG1)
•	Non-empty Payload

4
Verify
Client displays the response

Part B: Verifying client cache entry is still valid

5
Stimulus
Client is requested to send s confirmable GET request to
server’s resource so as to check if the resource was updated

6
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Another client-generated Message ID ≠ CMID (➔ CMID2)
•	Client-generated Token which may or may not be ≠ CTOK (➔ CTOK2)
•	Uri-Path option "validate"
•	Option Type = ETag, value = ETAG1 (the ETag value received in step 3)

7
Check
Server sends response containing:
•	Code = 67 (2.03 Valid)
•	Message ID = CMID2, Token = CTOK2
•	Option type = ETag, value = ETAG1
•	Empty Payload


8
Verify
Client displays the response

Part C: Verifying that client cache entry is no longer valid

9
Stimulus
Update the content of the server’s resource from a CoAP client (either another client, or the testing client in a separate transaction)

10
Stimulus
Client is requested to send a confirmable GET request to server’s resource so as to check if the resource was updated

11
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Another client-generated Message ID ≠ CMID and ≠ CMID2 (➔ CMID3)
•	Client-generated Token which may or may not be ≠ CTOK or CTOK2 (➔ CTOK3)
•	Uri-Path option "validate"
•	Option Type = ETag, value = ETAG1 (the ETag value received in step 3)

12
Check
Server sends response containing:
•	Code = 69 (2.05 Content)
•	Message ID = CMID3, Token = CTOK3
•	Option type = ETag, value = another ETag value ≠ ETAG1
•	The payload of the requested resource, which should be different from the payload in step 3


13
Verify
Client displays the response
"""

    def run(self):
        # Part A
        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=All(
                                           Opt(CoAPOptionUriPath("validate")),
                                           NoOpt(CoAPOptionETag()),
                                       )))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next_skip_ack()

        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.05,
                                              mid=CMID,
                                              tok=CTOK,
                                              opt=Opt(CoAPOptionETag()),
                                              pl=Not(b""))):
            raise self.Stop()

        ETAG1 = self.frame.coap["opt"][CoAPOptionETag]["val"]
        pl3 = self.frame.coap["pl"]

        self.next_skip_ack(optional=True)

        # Part B
        self.chain()

        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=Opt(
                                           CoAPOptionUriPath("validate"),
                                           CoAPOptionETag(ETAG1),
                                       )))
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
                                       code=2.03,
                                       mid=CMID2,
                                       tok=CTOK2,
                                       opt=Opt(CoAPOptionETag(ETAG1)),
                                       pl=b""))

        self.next_skip_ack(optional=True)

        # Part C
        self.chain()

        if self.match_coap("client", CoAP(code="put"), None):
            # allow an update from another client running on the same host
            self.next_skip_ack()
            self.match_coap("server", CoAP(code=2.04))
            self.next_skip_ack(optional=True)

            self.chain()

        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=Opt(
                                           CoAPOptionUriPath("validate"),
                                           CoAPOptionETag(ETAG1),
                                       )))
        CMID3 = self.frame.coap["mid"]
        CTOK3 = self.frame.coap["tok"]
        if CMID3 is Not(b''):
            if CMID3 == CMID or CMID3 == CMID2:
                self.setverdict("fail", "Message ID should be different")
        if CTOK3 is Not(b''):
            if CTOK3 == CTOK or CTOK3 == CTOK2:
                self.setverdict("fail", "Token should be different")

        self.next_skip_ack()

        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=2.05,
                                       mid=CMID3,
                                       tok=CTOK3,
                                       opt=Opt(CoAPOptionETag(Not(ETAG1))),
                                       pl=All(Not(b""), Not(pl3))))

        self.next_skip_ack(optional=True)
