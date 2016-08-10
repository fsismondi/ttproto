#!/usr/bin/env python3

from ..common import *
from ttproto.tat_coap.testcases.td_coap_core_18 import TD_COAP_CORE_18


class TD_COAP_CORE_24 (TD_COAP_CORE_18):
    """
---
TD_COAP_CORE_24:
    cfg: CoAP_CFG_03
    obj: Perform POST transaction with responses containing several
         Location-Path options (Reverse Proxy in CON mode)
    pre:
        - Proxy is configured as a reverse-proxy for the server
        - Proxy’s cache is cleared
        - Server accepts creation of new resource on /create2 and the created
          resource is located at /location1/location2/location3 (resource does
          not exist yet)
    ref: '[1] clause 5.8.1,5.10.8,5.9.1.1, 8.2.2,8.2.1,10.2.2,11.2'
    seq:
        -   s: Client is requested to send a confirmable POST request to proxy
        -   c:
            - The POST sent by the client contains:
            -   - Type = 0 (CON)
                - Code = 2 (POST)
                - An arbitrary payload
                - Content-format option
        -   c:
            - 'The Proxy forwards the POST request to server’s resource and
               that it contains:'
            -   - Type = 0 (CON)
                - Code = 2 (POST)
                - An arbitrary payload
                - Content-format option
        -   c:
            - 'Server sends a response to the proxy containing:'
            -   - Code = 65 (2.01 created)
                - Option type = Location-Path  (one for each segment)
                - 'Option values must contain "location1", "location2" &
                   "location3" without contain any "/"'
        -   c:
            - 'Observe that the Proxy forwards the response (in step 4) to
               client and check that the forwarded response contains:'
            -   - Code = 65 (2.01 created)
                - Option type = Location-Path  (one for each segment)
                - 'Option values must contain "location1", "location2" &
                   "location3" without contain any "/"'
        -   v: Client displays the response
        -   v:
            - Client interface returns the response
            -   - 2.01 created
                - Location: coap://proxy/location1/location2/location3
    """

    request_uri = "/create2"
    reverse_proxy = True
