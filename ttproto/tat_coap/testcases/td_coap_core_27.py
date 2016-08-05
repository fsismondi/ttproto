from ttproto.tat_coap.testcases.td_coap_core_22 import TD_COAP_CORE_22


class TD_COAP_CORE_27 (TD_COAP_CORE_22):
    """
---
TD_COAP_CORE_27:
    cfg: CoAP_CFG_03
    obj: Perform GET transaction with responses containing the ETag option and
         requests containing the If-Match option (CON mode)
    pre:
        - Proxy is configured as a reverse-proxy for the server
        - Proxy’s cache is cleared
        - Server should offer a /validate resource with resource content is not
          empty
        - Client & server supports ETag option and If-Match option
    ref: '[1] clause 5.8.1, 5.10.7,5.10.9,12.1.12, 8.2.2,8.2.1,10.2.2,11.2'
    seq:
        -   s: Client is requested to send a confirmable GET request to proxy
        -   c: Proxy forwards the request to server
        -   c:
            - 'Forwarded request must contain:'
            -   - Type = 0 (CON)
                - Code = 1 (GET)
        -   c:
            - 'Server sends response containing:'
            -   - Code = 69 (2.05 content)
                - Option type = ETag
                - Option value = an arbitrary ETag value
                - Not empty payload
        -   c: Proxy forwards the response to client
        -   s: Client is requested to send a confirmable PUT request to Proxy
        -   c:
            - 'Sent request must contain:'
            -   - Type = 0 (CON)
                - Code = 3 (PUT)
                - Option Type=If-Match
                - Option value=ETag value received in step 4
                - An arbitrary payload (which differs from the payload received
                  in step 3)
        -   v: Proxy forwards the request to servers resource & server updates
               the resource
        -   c:
            - 'Server sends response containing:'
            -   - Code = 68 (2.04 Changed)
                - Option type = ETag
                - Option value = an arbitrary ETag value which differs from the
                  ETag received in step 4
        -   c: Proxy forwards the response to client
        -   c:
            - 'Forwarded response contains:'
            -   - Code = 68 (2.04 Changed)
                - Option type = ETag
                - Option value = same ETag value found in step 8
        -   v: Client displays the response
        -   s: Update the content of the server’s resource from a CoAP client
        -   s: Client is requested to send s confirmable PUT request to proxy
               so as to perform an atomic update
        -   c:
            - 'Sent request must contain:'
            -   - Type = 0 (CON)
                - Code = 3 (PUT)
                - Option Type=If-Match
                - Option value=ETag value received in step 8
                - An arbitrary payload (which differs from the previous
                  payloads)
        -   c: Proxy forwards the request to server’s resource
        -   c:
            - 'Sent request must contain:'
            -   - Type = 0 (CON)
                - Code = 3 (PUT)
                - Option Type=If-Match
                - Option value=same ETag value found in step 14
                - An arbitrary payload (which differs from the previous
                  payloads)
        -   c:
            - 'Server sends response containing:'
            -   - Code = 140 (4.12 Precondition Failed)
        -   v: Proxy forwards the response to client
        -   c:
            - 'Response contains:'
            -   - Code = 140 (4.12 Precondition Failed)
        -   v: Client displays the response
    """

    reverse_proxy = True
