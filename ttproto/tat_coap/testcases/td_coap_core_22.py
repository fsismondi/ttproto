#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_22(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_22
Objective:
Perform GET transaction with responses containing the ETag option and requests
containing the If-Match option (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.1, 5.10.7,5.10.9,12.1.12

Pre-test
conditions:
•	Server offer a /validate resource
•	Client & server supports ETag and If-Match option
•	The Client‘s cache must be purged

Test Sequence:
Step
Type
Description
Preamble: client gets the resource


1
Stimulus
Client is requested to send a confirmable GET request to
server’s resource


2
Check
The request sent by the client contains:
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

Part A: single update

4
Stimulus
Client is requested to send a confirmable PUT request to
server’s resource so as to perform an atomic update

5
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Another client-generated Message ID ≠ CMID (➔ CMID2)
•	Client-generated Token which may or may not be ≠ CTOK (➔ CTOK2)
•	Content-format option
•	Uri-Path option "validate"
•	Option type = If-Match, value = ETAG1 (ETag value received in step 3)
•	An arbitrary payload (which differs from the payload received in step 3)

6
Check
Server sends response containing:
•	Code = 68 (2.04 Changed)
•	Message ID = CMID2, Token = CTOK2
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

7
Verify
Client displays the response and the server changed its
resource

Part B: concurrent updates


8
Stimulus
Client is requested to send a confirmable GET request to
server’s resource

9
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Another client-generated Message ID ≠ CMID and ≠ CMID2 (➔ CMID3)
•	Client-generated Token which may or may not be ≠ CTOK or CTOK2 (➔ CTOK3)
•	Uri-Path option "validate"

10
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Message ID = CMID3, Token = CTOK3
•	Option type = ETag, value = a value ≠ ETAG1 chosen by the server (➔ ETAG2)
•	The Payload sent in step 5

11
Verify
Client displays the response


12
Stimulus
Update the content of the server’s resource from a CoAP client

13
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Another client-generated Message ID ≠ CMID, CMID2, CMID3 (➔ CMID4)
•	Client-generated Token which may or may not be ≠ CTOK, CTOK2, CTOK3 (➔ CTOK4)
•	Content-format option
•	Uri-Path option "validate"
•	An arbitrary payload (which differs from the payloads received in steps 3 and 10)

14
Check
Server sends response containing:
•	Code = 2.04 (Changed)
•	Message ID = CMID4, Token = CTOK4
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

15
Verify
Client displays the response and the server changed its resource

16
Stimulus
Client is requested to send a confirmable PUT request to server’s resource so as to perform an atomic update, assuming it is still unchanged from step 10

17
Check
The request sent by the client contains:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Another client-generated Message ID ≠ CMID, CMID2, CMID3, CMID4 (➔ CMID5)
•	Client-generated Token which may or may not be ≠ CTOK, CTOK2, CTOK3, CTOK4 (➔ CTOK5)
•	Content-format option
•	Uri-Path option "validate"
•	Option type = If-Match, value = ETAG2 (ETag value received in step 10)
•	An arbitrary payload (which differs from the previous payloads)

18
Check
Server sends response containing:
•	Code = 4.12 (Precondition Failed)
•	Message ID = CMID4, Token = CTOK4
•	Optional Content-format option
•	Empty or non-empty Payload

19
Verify
Client displays the response and the server did not update the content of the resource
"""

    def run(self):
        # Preamble
        # Step 2
        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=All(
                                           Opt(CoAPOptionUriPath("validate")),
                                           NoOpt(CoAPOptionETag()),
                                       )))
        CMID = self.frame.coap["mid"]
        CTOK = self.frame.coap["tok"]

        self.next_skip_ack()

        # Step 3
        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.05,
                                              mid=CMID,
                                              tok=CTOK,
                                              opt=Opt(CoAPOptionETag()),
                                              pl=Not(b""))):
            raise self.Stop()

        ETAG1 = self.frame.coap["opt"][CoAPOptionETag]["val"]
        pl_3 = self.frame.coap["pl"]

        self.next_skip_ack(optional=True)

        # Part A
        self.chain()
        # Step 5
        self.match_coap("client", CoAP(type="con", code="put",
                                       opt=Opt(
                                           CoAPOptionContentFormat(),
                                           CoAPOptionUriPath("validate"),
                                           CoAPOptionIfMatch(ETAG1),
                                       ),
                                       pl=All(Not(b""), Not(pl_3))))
        CMID2 = self.frame.coap["mid"]
        CTOK2 = self.frame.coap["tok"]
        if CMID2 is Not(b''):
            if CMID2 == CMID:
                self.setverdict("fail", "Message ID should be different")
        if CTOK2 is Not(b''):
            if CTOK2 == CTOK:
                self.setverdict("fail", "Token should be different")
        pl_5 = self.frame.coap["pl"]
        self.next_skip_ack()

        # Step 6
        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.04,
                                              mid=CMID2,
                                              tok=CTOK2)):
            raise self.Stop()
        if self.match_coap("server", CoAP(pl=Not(b"")), None):
            self.match_coap("server", CoAP(
                opt=Opt(CoAPOptionContentFormat()),
            ), "fail")

        self.next_skip_ack(optional=True)

        # Part B

        # Step 9
        self.chain()

        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=Opt(CoAPOptionUriPath("validate"))))
        CMID3 = self.frame.coap["mid"]
        CTOK3 = self.frame.coap["tok"]
        if CMID3 is Not(b''):
            if CMID3 == CMID or CMID3 == CMID2:
                self.setverdict("fail", "Message ID should be different")
        if CTOK3 is Not(b''):
            if CTOK3 == CTOK or CTOK3 == CTOK2:
                self.setverdict("fail", "Token should be different")

        self.next_skip_ack()

        # Step 10
        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.05,
                                              mid=CMID3,
                                              tok=CTOK3,
                                              opt=Opt(CoAPOptionETag(Not(ETAG1))),
                                              pl=pl_5)):
            raise self.Stop()

        ETAG2 = self.frame.coap["opt"][CoAPOptionETag]["val"]
        pl_10 = self.frame.coap["pl"]

        self.next_skip_ack(optional=True)

        self.chain()

        # Step 13
        self.match_coap("client", CoAP(type="con", code="put",
                                       opt=Opt(
                                           CoAPOptionUriPath("validate"),
                                           CoAPOptionContentFormat(),
                                       ),
                                       pl=All(Not(b""), Not(pl_3), Not(pl_10))))
        CMID4 = self.frame.coap["mid"]
        CTOK4 = self.frame.coap["tok"]
        if CMID4 is Not(b''):
            if CMID4 == CMID or CMID4 == CMID2 or CMID4 == CMID3:
                self.setverdict("fail", "Message ID should be different")
        if CTOK4 is Not(b''):
            if CTOK4 == CTOK or CTOK4 == CTOK2 or CTOK4 == CTOK3:
                self.setverdict("fail", "Token should be different")
        pl_13 = self.frame.coap["pl"]

        self.next_skip_ack()

        # Step 14
        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=2.04,
                                       mid=CMID4,
                                       tok=CTOK4, ))
        if self.match_coap("server", CoAP(pl=Not(b"")), None):
            self.match_coap("server", CoAP(
                opt=Opt(CoAPOptionContentFormat()),
            ), "fail")

        self.next_skip_ack(optional=True)

        self.chain()

        # Step 17
        self.match_coap("client", CoAP(type="con", code="put",
                                       opt=Opt(
                                           CoAPOptionContentFormat(),
                                           CoAPOptionUriPath("validate"),
                                           CoAPOptionIfMatch(ETAG2),
                                       ),
                                       pl=All(Not(b""), Not(pl_13))))
        CMID5 = self.frame.coap["mid"]
        CTOK5 = self.frame.coap["tok"]
        if CMID5 is Not(b''):
            if CMID5 == CMID or CMID5 == CMID2 or CMID5 == CMID3 or CMID5 == CMID4:
                self.setverdict("fail", "Message ID should be different")
        if CTOK5 is Not(b''):
            if CTOK5 == CTOK or CTOK5 == CTOK2 or CTOK5 == CTOK3 or CTOK5 == CTOK4:
                self.setverdict("fail", "Token should be different")

        self.next_skip_ack()
        # Step 18
        self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                       code=4.12,
                                       mid=CMID5,
                                       tok=CTOK5, ))
