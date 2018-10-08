from ..common import *


class TD_COAP_CORE_17(CoAPTestCase):
    """
---
TD_COAP_CORE_17:
    cfg: CoAP_CFG_BASIC
    obj: Perform GET transaction with a separate response (NON mode)
    pre: Server offers a resource /separate which is not served immediately
        and which therefore is not acknowledged in a piggybacked way.
    ref: '[COAP] 2.2, 5.2.2, 5.8.1'
    seq:
    -   s: "Client is requested to send a non-confirmable GET request to\
            \ server\u2019s resource"
    -   c:
        - 'The request sent by the client contains:'
        -   - Type = 1 (NON)
            - Code = 1 (GET)
            - "Client-generated Message ID (\u2794 CMID)"
            - Uri-Path option "separate"
    -   c:
        - 'Server DOES NOT send response containing:'
        -   - Type = 2 (ACK)
            - Same message ID as in the request in step 2
            - Empty Payload
    -   n: Some time (a couple of seconds) elapses.
    -   c:
        - 'Server sends response containing:'
        -   - Type = 1 (NON)
            - Code = 2.05 (Content)
            - "Server-generated Message ID (\u2794 SMID)"
            - Content-format option
            - Non-empty Payload
    -   v: Client displays the response
    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]

        .. note::
            Check the number/value of the uri query options or not?
        """
        return [
            CoAP(type='non',
                 code='get',
                 opt=Opt(CoAPOptionUriPath("separate"))
                 )
        ]

    def run(self):
        self.match("client", CoAP(type="non", code="get", opt=self.uri("/separate")))

        self.next()

        # FIXME: may be out-of-order
        if self.coap in CoAP(type="ack"):
            self.set_verdict("fail", "server must no send any ack")
            self.next()

        if self.match("server", CoAP(type="non", code=2.05)):
            self.match("server", CoAP(pl=Not(b''), opt=Opt(CoAPOptionContentFormat())), "fail")
