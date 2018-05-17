from ..common import *
from ...core.templates import Range

class TD_COAP_BLOCK_01(CoAPTestCase):

    """
---
TD_COAP_BLOCK_01:
    obj: Handle GET blockwise transfer for large resource (early negotiation)
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2-2.4'

    pre:
        - Client supports Block2 transfers
        - Server supports Block2 transfers
        - Server offers a large resource /large
        - Client knows /large requires block transfer

    seq:
    -   s: "Client is requested to retrieve resource /large"

    -   c:
        - 'Client sends a GET request. The request optionally contains
        a Block2 option indicating:'
        -   - NUM = 0;
            - M = 0;
            - SZX = the desired block size.

    -   c:
    - 'Server sends 2.05 (Content) response with a Block2 option
    indicating:'
    -   - NUM = 0;
        - M = 1;
        - "SZX is less or equal to the desired block size indicated
        by the GET request"
        - Payload size is 2SZX+4 bytes.

    -   c:
        - 'Client send GET requests for further blocks indicating:'
        -   - 'NUM = i where “i” is the block number of the current
        block'
            - M = 0
            - SZX is the SZX at step 3

    -   c:
        - 'Server sends 2.05 (Content) response containing Block2
        option indicating:'
        -   - NUM = i where “i” is the block number used at step 4
            - M = 1
            - SZX is the SZX at step 3
            - Payload size MUST be 2SZX+4 bytes

    -   c:
    - 'Client send GET request for the last block indicating:'
    -   - NUM = n where “n” is the last block number
        - M = 0
        - SZX is the SZX at step 3

    -   c:
        - 'Server sends 2.05 (Content) response with a Block2 option
        indicating:'
        -   - NUM = n where “n” is the block number used at step 6;
            - M = 0;
            - SZX is the SZX at step 3.
            - Payload size is lesser or equal to 2SZX+4 bytes.

    -   v: 'Client displays the received information'

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
        self.match("client", CoAP (code = "get",
                         opt = self.uri ("/large", CoAPOptionBlock2(num=0))))
        self.match("client", CoAP (opt = Opt (CoAPOptionBlock2(m=0))), "fail")
        client_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]

        self.next_skip_ack()

        # Step 3 - response from the server w/ block size negociation
        if not self.match("server", CoAP (code = 2.05,
                         opt = Opt (CoAPOptionBlock2 ())
                )):
            raise self.Stop()
        self.match("server", CoAP (opt = Opt (CoAPOptionBlock2 (num=0, szx=Range(int, 0, client_szx)))
                ), "fail")

        server_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]
        server_size = 2**(server_szx+4)

        # Step 3 - expect more blocks
        self.match("server", CoAP (opt = Opt (CoAPOptionBlock2(m=1)),
                         pl = Length (bytes, server_size)
                ))

        # Step 4 - 5
        for i in itertools.count(1):
            self.next_skip_ack()

            # Step 4 - request next block from client
            # (This is Step 6 if last block.)
            if self.match("client", CoAP (code = "get",
                             opt = Opt (CoAPOptionBlock2 (num=i, szx=server_szx)))):
                self.match("client", CoAP (opt = Opt (CoAPOptionBlock2 (m=0))), "fail")

            self.next_skip_ack()

            # Step 5 - send next block from server
            if not self.match("server", CoAP (code = 2.05,
                             opt = Opt (CoAPOptionBlock2 (num=i, szx=server_szx))
                    )):
                break

            if not self.match("server", CoAP (opt = Opt (CoAPOptionBlock2 (m=1)),
                                pl = Length (bytes, server_size)
                        ), None):
                # Step 7 - no more blocks
                self.match("server", CoAP (opt = Opt (CoAPOptionBlock2 (m=0)),
                                pl = Length (bytes, (1, server_size))
                        ), "fail")

                # end of testcase
                self.next_skip_ack(optional = True)
                break
