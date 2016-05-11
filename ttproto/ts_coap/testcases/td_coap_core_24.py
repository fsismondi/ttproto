#!/usr/bin/env python3

from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *
from ttproto.ts_coap.testcases.td_coap_core_18 import TD_COAP_CORE_18


class TD_COAP_CORE_24(TD_COAP_CORE_18):
    """Identifier:
TD_COAP_CORE_24
Objective:
Perform POST transaction with responses containing several Location-Path options
(Reverse Proxy in CON mode)
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1,5.10.8,5.9.1.1, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•	Proxy is configured as a reverse-proxy for the server
•	Proxy’s cache is cleared
•	Server accepts creation of new resource on /create2 and the created resource is
located at  /location1/location2/location3 (resource does not exist yet)


Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a confirmable POST request to
proxy

2
Check
The POST sent by the client contains:
•	Type = 0 (CON)
•	Code = 2 (POST)
•	An arbitrary payload
•	Content-format option


3
Check
The Proxy forwards the POST request to server’s resource
and that it contains:
•	Type = 0 (CON)
•	Code = 2 (POST)
•	An arbitrary payload
•	Content-format option

4
Check
Server sends a response to the proxy containing:
•	Code = 65 (2.01 created)
•	Option type = Location-Path  (one for each segment)
•	Option values must contain “location1”, “location2” &
“location3” without contain any ‘/’


5
Check/
Observe that the Proxy forwards the response (in step 4) to
client and check that the forwarded response contains:
•	Code = 65 (2.01 created)
•	Option type = Location-Path  (one for each segment)
•	Option values must contain “location1”, “location2” &
“location3” without contain any ‘/’

6
Verify
Client displays the response

7
Verify
Client interface returns the response
•	2.01 created
•	Location: coap://proxy/location1/location2/location3
	"""
    request_uri = "/create2"
    reverse_proxy = True
