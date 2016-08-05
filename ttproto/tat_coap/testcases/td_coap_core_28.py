from ttproto.tat_coap.testcases.td_coap_core_23 import TD_COAP_CORE_23


class TD_COAP_CORE_28 (TD_COAP_CORE_23):
    """
---
TD_COAP_CORE_28:
    cfg: CoAP_CFG_03
    obj: Perform GET transaction with responses containing the ETag option and
         requests containing the If-None-Match option (CON mode)
         (Reverse proxy)
    pre:
        - Proxy is configured as a reverse-proxy for the server
        - Proxy’s cache is cleared
        - Server should offer a /create3 resource, which does not exist and
          which can be created by the client
        - Client & server supports If-None-Match
    ref: '[1] clause 5.8.1, 5.10.7,5.10.10,12.1.12, 8.2.2,8.2.1,10.2.2,11.2'
    seq:
    -   s: Client is requested to send a confirmable PUT request to proxy to
           atomically create resource in server
    -   c: Proxy forwards the request to server
    -   c:
        - 'Forwarded t request must contain:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - Option Type=If-None-Match
            - An arbitrary payload
    -   c:
        - 'Server sends response containing:'
        -   - Code = 65 (2.01 Created)
    -   c: Proxy forwards the response to client
    -   v: Client displays the response & and server created new resource
    -   s: Client is requested to send s confirmable PUT request to proxy to
           atomically create resource in server
    -   c:
        - 'Sent request must contain:'
        -   - Type = 0 (CON)
            - Code = 3 (PUT)
            - Option Type=If-Non-Match
            - Option value=Received ETag value
    -   c:
        - 'Server sends response containing:'
        -   - 140 (4.12 Precondition Failed)
    -   v: Proxy forwards the response to client
    -   c:
        - 'Response contains:'
        -   - 140 (4.12 Precondition Failed)
    -   v: Client displays the response
    """

    request_uri = "/create3"
    reverse_proxy = True
