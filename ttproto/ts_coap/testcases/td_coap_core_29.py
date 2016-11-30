#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *


class TD_COAP_CORE_29(CoAPTestcase):
    """Identifier:
TD_COAP_CORE_29
Objective:
Perform GET transaction with responses containing the Max-Age option (Reverse
proxy)
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1,5.10.6,5.9.1.3,5.9.1.5, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•	Proxy offers a cache
•	Proxy is configured as a reverse-proxy for the server
•	Servers resource vary in time and supports Max-Age option
•	Proxy’s cache is cleared
•	Server offers a resource /validate that varies in time, with a Max-Age set to 30s

Test Sequence:
Step
Type
Description

1
Stimulus
A confirmable GET request is sent to Proxy from Client


2
Check
Proxy Sends request containing:
•	Type = 0 (CON)
•	Code = 1 (GET)


3
Check
Server sends response containing:
•	Code = 69 (2.05 Content)
•	Option type = ETag
•	Option value = ETag value
•	Option type = Max-age
•	Option value
•	Not empty Payload


4
Verify
Proxy forwards response to client

5
Stimulus
A confirmable GET request is sent to proxy from Client before
Max-Age expires

6
Check
Proxy dos not forward any request to the server

7
Check
Proxy sends response to client

8
Verify
Response contains:
•	Option type = Max-age
•	Option Value = new Max-age
•	Payload cached
	"""
    reverse_proxy = True

    def run(self):
        # Step 2
        self.match_coap("client", CoAP(type="con", code="get",
                                       opt=All(
                                           Opt(CoAPOptionUriPath("validate")),
                                           NoOpt(CoAPOptionETag()),
                                       )))

        self.next_skip_ack()

        if not self.match_coap("server", CoAP(type=Any(CoAPType("con"), "ack"),
                                              code=2.05,
                                              opt=Opt(CoAPOptionETag(), CoAPOptionMaxAge()),
                                              pl=Not(b""))):
            raise self.Stop()

        maxage = self.frame.coap["opt"][CoAPOptionMaxAge]["val"]

        ts = self.frame.ts

        self.next_skip_ack(optional=True)

        while self.chain(optional=True):
            interval = self.frame.ts - ts

            if interval >= maxage:
                break

            if self.match_coap("client", CoAP(type="con", code="get",
                                              opt=Opt(CoAPOptionUriPath("validate"))),
                               None):
                raise self.setverdict("inconclusive",
                                      "Proxy sent a new GET request after %.1f seconds whereas Max-Age is set to %d seconds" % (
                                      interval, maxage))
                raise self.Stop()

            while self.next(optional=True):
                pass

        self.setverdict("pass", "No further GET requests were observed within Max-Age (%d) seconds" % maxage)
