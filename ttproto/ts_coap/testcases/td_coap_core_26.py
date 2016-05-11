#!/usr/bin/env python3

#from ttproto.ts_coap.proto_specific import CoAPTestcase
# from ttproto.ts_coap.proto_templates import *
from ttproto.ts_coap.testcases.td_coap_core_20 import TD_COAP_CORE_20

class TD_COAP_CORE_26 (TD_COAP_CORE_20):
	"""Identifier:
TD_COAP_CORE_26
Objective:
Perform GET transaction containing the Accept option (CON mode
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1,5.10.5,5.10.4, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•	Proxy is configured as a reverse-proxy for the server
•	Proxy’s cache is cleared
•	Server should provide a resource /multi-format which exists in two formats:
-	text/plain;charset=utf-8
-	application/xml

Test Sequence:
Step
Type
Description
Part A: client requests text format


1
Stimulus
Client is requested to send a confirmable GET request to
proxy

2
Check
Proxy receives the request from client  & forwards it to
server’s resource


3
Check
Forwarded request must contain:
•	Type = 0 (CON)
•	Code = 1 (GET)
•	Option: type = Accept, value = 0 (text/plain;charset=utf-8)

4
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Option: type = Content-Format, value = 0
(text/plain;charset=utf-8)
•	Payload = Content of the requested resource in
text/plain;charset=utf-8 format

5
Check
Proxy forwards the response to client

6
Verify
Client receives  & displays the response

7
Check
Response contains:
•	Code = 69 (2.05 content)
•	Option: type = Content-Format, value = 0
(text/plain;charset=utf-8)
•	Payload = Content of the requested resource in
text/plain;charset=utf-8 format

Part B: client requests xml format

8
Stimulus
Client is requested to send a confirmable GET request to
Proxy

9
Check
Proxy forwards the request to server

10
Check
Sent request must contain:
•	Type = 0 (CON)
•	Code = 1 (GET)
Option: type = Accept, value = 41 (application/xml)

11
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Option: type = Content-Format, value = 41
(application/xml)
Payload = Content of the requested resource in
application/xml format

12
Check
Proxy forwards the response to client

13
Verify
Client receives & displays the response

14
Check
Client displays the response received:
•	Code = 69 (2.05 content)
•	Option: type = Content-Format, value = 41
(application/xml)
Payload = Content of the requested resource in
application/xml format
	"""
	reverse_proxy = True

