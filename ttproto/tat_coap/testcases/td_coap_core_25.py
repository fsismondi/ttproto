from ttproto.tat_coap.testcases.td_coap_core_19 import TD_COAP_CORE_19


class TD_COAP_CORE_25 (TD_COAP_CORE_19):
    """
---
TD_COAP_CORE_25:
    cfg: CoAP_CFG_03
    obj: Perform POST transaction with responses containing several
         Location-Query option (Reverse proxy)
    pre:
        - Proxy is configured as a reverse-proxy for the server
        - Proxy’s cache is cleared
        - Server accepts creation of new resource on uri  /location-query, the
          location of the created resource contains two query parameters
          ?first=1&second=2
    ref: '[1] clause 5.8.1,5.10.8,5.9.1.1, 8.2.2,8.2.1,10.2.2,11.2'
    seq:
        -   s: Client is requested to send a confirmable POST request to proxy
        -   c: Proxy receives the request from client  & forwards it to
               server's resource
        -   c:
            - 'Forwarded request must contain:'
            -   - Type = 0 (CON)
                - Code = 2 (POST)
                - An arbitrary payload
                - Content-format option
        -   c:
            - 'Server sends response to proxy containing:'
            -   - Code = 65 (2.01 created)
                - Two options whose type is Location-Query
                - The first option contains first=1
                - The second option contains second=2
        -   c: Proxy forwards the response to client
        -   c: Client displays the message
        -   v:
            - 'Client interface returns the response:'
            -   - 2.01 created
                - Location: coap://proxy/?first=1&second=2
    """

    reverse_proxy = True
