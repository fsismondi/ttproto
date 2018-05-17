from ..common import *
from ...core.templates import Range


class TD_COAP_BLOCK_03(CoAPTestCase):
    """
---
TD_COAP_BLOCK_03:
    obj: Handle PUT blockwise transfer for large resource
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2, 2.3, 2.5'

    pre:
        - Client supports Block1 transfers
        - Server supports Block1 transfers
        - Server offers a large updatable resource /large-update

    seq:
    -   s: "Client is requested to update resource /large-update on
    Server"

    -   c:
        - 'Client sends a PUT request containing Block1 option
        indicating:'
        -   - NUM = 0
            - M = 1
            - SZX = the desired block size
            - Payload size is 2SZX+4 bytes

    -   c:
        - 'Server sends 2.04 (Changed) or 2.31 (Continue) response with a Block1 option
        indicating:'
        -   - NUM = 0
            - "M = 0 (stateless for 2.04) or 1 (atomic,for 2.31)"
            - SZX is less or equal to the SZX at step 2

    -   c:
        - 'Client sends further requests containing Block1 option
        indicating:'
        -   - NUM = "i where \\“i\\” is the block number of the current
                    block. If the server decreased the SZX parameter in
                    step 3, then the client should adapt the block size
                    accordingly and may resume the transfer from block
                    id 2size_in_step_2-size_in_step_3 instead of block 1)"
            - M = 1
            - SZX is the SZX at step 3
            - Payload size is 2SZX+4 bytes

    -   c:
        - 'Server sends 2.04 (Changed) or 2.31 (Continue) response containing Block1
        option indicating:'
        -   - NUM = i where “i” is the block number used at step 4
            - M = 0 (stateless, for 2.04) or 1 (atomic, for 2.31)
            - SZX is the SZX at step 3

    -   c:
        - 'Client send PUT request containing the last block and
        indicating:'
        -   - NUM = n where “n” is the last block number
            - M = 0
            - SZX is the SZX at step 3
            - Payload size is lesser or equal to 2SZX+4

    -   c:
        - 'Server sends 2.04 (Changed) response with a Block1 option
        indicating:'
        -   - NUM = n where “n” is the block number used at step 6
            - M = 0
            - SZX is the SZX at step 3

    -   v: "Server indicates presence of the complete updated resource
    /large-update"

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
            CoAP(type='con', code='put', opt=Opt(CoAPOptionUriPath("large-update"))),
        ]

    def run (self):
        # Step 2 - initial request from the client
        self.match("client", CoAP (code = "put",
                         opt = self.uri ("/large-update", CoAPOptionBlock1 (num=0, m=1))))
        client_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
        client_size = 2**(client_szx+4)
        self.match("client", CoAP (pl = Length (bytes, client_size)), "fail")

        self.next_skip_ack()

        # Step 3 - response from the server possibly w/ block size negociation
        if not self.match("server", CoAP (code = Any (CoAPCode (2.04), 2.31),
                         opt = Opt (CoAPOptionBlock1 (num=0, szx=Range(int, 0, client_szx)))
                )):
            return
        server_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
        server_size = 2**(server_szx+4)

        self.next_skip_ack()

        # next block should have num 1
        counter = itertools.count(1)

        if server_szx != client_szx:
            # client & server do not agree on the block size

            # server requested a smaller block size, num may be bigger
            if (self.match("client", CoAP (opt = Opt (CoAPOptionBlock1()))), None):
                num = self.coap["opt"][CoAPOptionBlock1]
                if num > 1:
                    counter = itertools.count(num)

        for i in counter:

            # Step 4 - send next block from client
            self.match("client", CoAP (code = "put",
                             opt = Opt (CoAPOptionBlock1 (num=i, szx=server_szx))
                    ))


            last = not self.match("client", CoAP (    opt = Opt (CoAPOptionBlock1 (m=1)),
                                    pl = Length (bytes, server_size)
                    ), None)
            if last:
                # Step 6 - last block
                self.match("client", CoAP (    opt = Opt (CoAPOptionBlock1 (m=0)),
                                    pl = Length (bytes, (1, server_size))
                        ), "fail")

            self.next_skip_ack()

            # Step 5 / Step 7 - ack from the server
            self.match("server", CoAP (code = Any (CoAPCode (2.04), 2.31),
                             opt = Opt (CoAPOptionBlock1 (num=i, szx=server_szx))
                    ))

            if last:
                self.next_skip_ack (optional = True)
                break

            self.next_skip_ack()
