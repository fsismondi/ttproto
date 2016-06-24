#!/usr/bin/env python3

#from ttproto.ts_coap.proto_specific import CoAPTestcase
from ttproto.ts_coap.proto_templates import *
from ttproto.ts_coap.testcases.td_coap_core_19 import TD_COAP_CORE_19


class TD_COAP_CORE_25 (TD_COAP_CORE_19):
    """Identifier:
TD_COAP_CORE_25
Objective:
Perform POST transaction with  responses containing several Location- Query  option
(Reverse proxy)
Configuration:
CoAP_CFG_03
References:
[1] clause 5.8.1,5.10.8,5.9.1.1, 8.2.2,8.2.1,10.2.2,11.2

Pre-test
conditions:
•   Proxy is configured as a reverse-proxy for the server
•   Proxy’s cache is cleared
•   Server accepts creation of new resource on uri  /location-query, the location of
the created resource contains two query parameters ?first=1&second=2

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
Proxy receives the request from client  & forwards it to
server’s resource


3
Check
Forwarded request must contain:
•   Type = 0 (CON)
•   Code = 2 (POST)
•   An arbitrary payload
•   Content-format option

4
Check
Server sends response to proxy containing:
•	Code = 65 (2.01 created)
•	Two options whose type is Location-Query
	The first option contains first=1
	The second option contains second=2

5
Check
Proxy forwards the response to client

6
Check
Client displays  the message

7
Verify
Client interface returns the response:
•	2.01 created
•	Location: coap://proxy/?first=1&second=2
	"""
    reverse_proxy = True

