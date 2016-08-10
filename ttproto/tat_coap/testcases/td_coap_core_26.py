from ttproto.tat_coap.testcases.td_coap_core_20 import TD_COAP_CORE_20


class TD_COAP_CORE_26 (TD_COAP_CORE_20):
    """
---
TD_COAP_CORE_26:
    cfg: CoAP_CFG_03
    obj: Perform GET transaction containing the Accept option (CON mode)
    pre:
        - Proxy is configured as a reverse-proxy for the server
        - Proxy’s cache is cleared
        - 'Server should provide a resource /multi-format which exists in two
           formats:'
        -   - text/plain;charset=utf-8
            - application/xml
    ref: '[1] clause 5.8.1,5.10.5,5.10.4, 8.2.2,8.2.1,10.2.2,11.2'
    seq:
        -   s: Client is requested to send a confirmable GET request to proxy
        -   c: Proxy receives the request from client & forwards it to
               server's resource
        -   c:
            - 'Forwarded request must contain:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
                - 'Option: type = Accept, value = 0 (text/plain;charset=utf-8)'
        -   c:
            - 'Server sends response containing:'
            -   - Code = 69 (2.05 content)
                - 'Option: type = Content-Format, value = 0\
                   (text/plain;charset=utf-8)'
                - Payload = Content of the requested resource in
                  text/plain;charset=utf-8 format
        -   c: Proxy forwards the response to client
        -   v: Client receives & displays the response
        -   c:
            - 'Response contains:'
            - Code = 69 (2.05 content)
            - 'Option: type = Content-Format, value = 0\
               (text/plain;charset=utf-8)'
            - Payload = Content of the requested resource in
              text/plain;charset=utf-8 format
        -   s: Client is requested to send a confirmable GET request to Proxy
        -   c: Proxy forwards the request to server
        -   c:
            - 'Sent request must contain:'
            -   - Type = 0 (CON)
                - 'Code = 1 (GET) Option: type = Accept, value = 41\
                   (application/xml)'
        -   c:
            - 'Server sends response containing:'
            -   - Code = 69 (2.05 content)
                - 'Option: type = Content-Format, value = 41\
                   (application/xml)'
                - Payload = Content of the requested resource in
                  application/xml format
        -   c: Proxy forwards the response to client
        -   v: Client receives & displays the response
        -   c:
            - 'Client displays the response received:'
            -   - Code = 69 (2.05 content)
                - 'Option: type = Content-Format, value = 41\
                   (application/xml)'
                - Payload = Content of the requested resource in
                  application/xml format
    """

    reverse_proxy = True
