from ..common import *


class TD_COAP_CORE_07(CoAPTestCase):
    """
---
TD_COAP_CORE_07:
    cfg: CoAP_CFG_BASIC
    obj: Perform PUT transaction (NON mode)
    pre: Server offers a /test resource that handles PUT
    ref: '[COAP] 5.8.3, 5.2.3'
    seq:
    -   s:
        - 'Client is requested to send a PUT request with:'
        -   - Type = 1 (NON)
            - Code = 3 (PUT)
            - An arbitrary payload
            - Content-format option
    -   c:
        - 'The request sent by the client contains:'
        -   - Type=1 and Code=3
            - "Client-generated Message ID (\u2794 CMID)"
            - "Client-generated Token (\u2794 CTOK)"
            - Uri-Path option "test"
    -   v: Server displays the received information
    -   c:
        - 'Server sends response containing:'
        -   - Type = 1 (NON)
            - Code = 2.04 (Changed) or 2.01 (Created)
            - "Server-generated Message ID (\u2794 SMID)"
            - Token = CTOK
            - Content-format option if payload non-empty
            - Empty or non-empty Payload
    -   v: Client displays the received response
    """

    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        # TODO client message w/ no content format and payload -> fail?
        return [
            CoAP(
                type='non',
                code='put',
                pl=Not(b''),
                opt=Opt(CoAPOptionContentFormat(), CoAPOptionUriPath("test"))
            )
        ]

    def run(self):
        if self._frame is None: #inconclusive instead of error is no frame at all.
            return
        self.match("client", CoAP(type="non", code="put", opt=self.uri("/test")))
        self.match("client", CoAP(pl=Not(b''), opt=Opt(CoAPOptionContentFormat()), ), "inconclusive")

        CTOK = self.coap["tok"]

        self.next()

        self.match("server", CoAP(type="non", code=Any(65, 68), tok=CTOK))

        if self.match('server', CoAP(pl=Not(b'')), None):
            self.match("server", CoAP(opt=Opt(CoAPOptionContentFormat())), "fail")
