#!/usr/bin/env python3

#from ttproto.ts_coap.proto_specific import CoAPTestcase
# from ttproto.ts_coap.proto_templates import *
from ttproto.ts_coap.testcases.td_coap_core_22 import TD_COAP_CORE_22

class TD_COAP_CORE_27 (TD_COAP_CORE_22):
	"""Identifier:
TD_COAP_CORE_27
Objective:
Perform GET transaction with responses containing the ETag option and requests
containing the If-Match option (CON mode)
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1, 5.10.7,5.10.9,12.1.12, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•	Proxy is configured as a reverse-proxy for the server
•	Proxy’s cache is cleared
•	Server should offer a /validate resource with resource content is not empty
•	Client & server supports ETag option and If-Match option

Test Sequence:
Step
Type
Description
Preamble: client gets the resource


1
Stimulus
Client is requested to send a confirmable GET request to
proxy

2
Check
Proxy forwards the request to server


3
Check
Forwarded request must contain:
•	Type = 0 (CON)
•	Code = 1 (GET)

4
Check
Server sends response containing:
•	Code = 69 (2.05 content)
•	Option type = ETag
•	Option value = an arbitrary ETag value
•	Not empty payload

5
Check
Proxy forwards the response to client
Part A: single update

6
Stimulus
Client is requested to send a confirmable PUT request to
Proxy

7
Check
Sent request must contain:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Option Type=If-Match
•	Option value=ETag value received in step 4
•	An arbitrary payload (which differs from the payload
received in step 3)

8
Verify
Proxy forwards the request to servers resource & server
updates the resource


9
Check
Server sends response containing:
•	Code = 68 (2.04 Changed)
•	Option type = ETag
•	Option value = an arbitrary ETag value which differs from
the ETag received in step 4


10
Check
Proxy forwards the response to client

11
Check
Forwarded response contains:
•	Code = 68 (2.04 Changed)
•	Option type = ETag
•	Option value = same ETag value found in step 8


12
Verify
Client displays the response
Part B: concurrent updates

13
Stimulus
Update the content of the server’s resource from a CoAP
client

14
Stimulus
Client is requested to send s confirmable PUT request to
proxy so as to perform an atomic update

15
Check
Sent request must contain:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Option Type=If-Match
•	Option value=ETag value received in step 8
An arbitrary payload (which differs from the previous
payloads)

16
Check
Proxy forwards the request to server’s resource

17
Check
Sent request must contain:
•	Type = 0 (CON)
•	Code = 3 (PUT)
•	Option Type=If-Match
•	Option value=same ETag value found in step 14
An arbitrary payload (which differs from the previous
payloads)

18
Check
Server sends response containing:
•	Code = 140 (4.12 Precondition Failed)


19
Verify
Proxy forwards the response to client

20
Check
Response contains:
Code = 140 (4.12 Precondition Failed)

21
Verify
Client displays the response
	"""
	reverse_proxy = True


