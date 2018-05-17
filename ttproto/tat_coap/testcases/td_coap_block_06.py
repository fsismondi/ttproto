from ..common import *
from ...core.templates import Range

class TD_COAP_BLOCK_06(CoAPTestCase):
    """
---
TD_COAP_BLOCK_06:
    obj: Handle GET blockwise transfer for large resource (early negotiation, 16 byte block size)
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2-2.4'

    pre:
        - Client supports Block2 transfers
        - Server supports Block2 transfers
        - Server offers a large resource /large
        - Client does not know /large requires block transfer

    seq:
    -   s: "Client is requested to retrieve resource /large"

    -   c:
        - 'Client sends a GET request not containing Block2 option indicating:'
        -   - NUM = 0
            - M = 0
            - "SZX (➔DES_SZX) is the desired block size"

    -   c:
        - 'Server sends 2.05 (Content) response with a Block2 option
        indicating:'
        -   - NUM = 0
            - M = 1
            - "SZX = (➔ACT_SZX) is less than or equal to DES_SZX."
            - "Payload size is 2SZX+4 bytes"

    -   c:
        - 'Client send GET requests for further blocks indicating:'
        -   - NUM = i where “i” is the block number of the current block
            - M = 0
            - SZX is ACT_SZX

    -   c:
        - 'Server sends 2.05 (Content) response with a Block2 option
        indicating:'
        -   - NUM = i where “i” is the block number used at step 4
            - M = 1
            - SZX is the ACT_SZX
            - Payload size is 2SZX+4 bytes

    -   c:
        - 'Client send GET request for the last block indicating:'
        - NUM = n where “n” is the last block number;
        - M = 0;
        - SZX is the ACT_SZX

    -   c:
        - 'Server sends 2.05 (Content) response with a Block2 option
        indicating:'
        - NUM = n where “n” is the block number used at step 8
        - M = 0
        - SZX is the ACT_SZX
        - Payload size is lesser or equal to 2SZX+4

    -   v: Client displays the received information

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
        return [
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("large"),CoAPOptionBlock2())),
        ]

    def run (self):
        # Step 2 - initial request from the client
        self.match("client", CoAP(code = "get",
                opt = self.uri("/large", Opt(CoAPOptionBlock2(num=0,m=0)))))
        client_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]
        client_num  = self.coap["opt"][CoAPOptionBlock2]["num"]
        self.next_skip_ack()


        # Step 3 - response from the server w/ block size negociation
        self.match("server", CoAP (code = 2.05,
            opt = Opt(CoAPOptionBlock2(num=0,szx=Range(int, 0, client_szx)))
                    ), "fail")
        server_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]
        server_size = 2**(server_szx+4)

        # Step 3 - expect more blocks
        self.match("server", CoAP(opt = Opt(CoAPOptionBlock2(m=1)),
                                    pl = Length(bytes, server_size)
        ))

        self.next_skip_ack()

        verdict_if_none = "inconclusive"
        client_num += 1
        # Step 4 - request next block from client
        while self.match("client", CoAP(code = "get",
                    opt = Opt(CoAPOptionBlock2(num=client_num, szx=server_szx)))
                    , verdict_if_none):

            self.match("client", CoAP (opt = Opt(CoAPOptionBlock2(m=0))),
                        "fail")

            self.next_skip_ack()
            # Step 5 - send next block from server
            if not self.match("server", CoAP(code = 2.05,
                            opt = Opt(CoAPOptionBlock2(num=client_num, szx=server_szx))
                    )):
                break
            if not self.match("server", CoAP(opt = Opt(CoAPOptionBlock2(m=1)),
                                                pl = Length(bytes, server_size)
                                ), None):
                # Step 7 - no more blocks
                self.match("server", CoAP (opt = Opt(CoAPOptionBlock2(m=0)),
                                            pl = Length(bytes, (1, server_size))
                            ), "fail")
                verdict_if_none = None
                # end of testcase
                self.next_skip_ack(optional = True)
                break
            self.next_skip_ack()

            # The expected block number increase for each block.
            client_num += 1
