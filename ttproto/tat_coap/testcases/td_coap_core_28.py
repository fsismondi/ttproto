#!/usr/bin/env python3

#from ttproto.ts_coap.proto_specific import CoAPTestcase
# from ttproto.ts_coap.proto_templates import *
from ttproto.ts_coap.testcases.td_coap_core_23 import TD_COAP_CORE_23

class TD_COAP_CORE_28 (TD_COAP_CORE_23):
	"""Identifier:
TD_COAP_CORE_28
Objective:
Perform GET transaction with responses containing the ETag option and requests
containing the If-None-Match option (CON mode) (Reverse proxy)
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1, 5.10.7,5.10.10,12.1.12, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•	 Proxy is configured as a reverse-proxy for the server
•	Proxy’s cache is cleared
•	Server should offer a /create3 resource, which does not exist and which can be
created by the client
•	Client & server supports If-None-Match


Test Sequence:
Step
Type
Description
Part A: single creation


1
Stimulus
Client is requested to send a confirmable PUT request to
proxy to atomically create resource in server

2
Check
Proxy forwards the request to server


3
Check
Forwarded t request must contain:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Option Type=If-None-Match
•	An arbitrary payload

4
Check
Server sends response containing:
•	Code = 65 (2.01 Created)


5
Check
Proxy forwards the response to client

6
Verify
Client displays the response & and server created new
resource
Part B: concurrent creations


5
Stimulus
Client is requested to send s confirmable PUT request to
proxy to atomically create resource in server

6
Check
Sent request must contain:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Option Type=If-Non-Match
•	Option value=Received ETag value

7
Check
Server sends response containing:
•	140 (4.12 Precondition Failed)

8
Verify
Proxy forwards the response to client

9
Check
Response contains:
•  140 (4.12 Precondition Failed)

10
Verify
Client displays the response
	"""
	request_uri = "/create3"
	reverse_proxy = True
