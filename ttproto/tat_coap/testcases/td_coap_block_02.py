from ..common import *
from ...core.templates import Length, Range


class TD_COAP_BLOCK_02(CoAPTestCase):
    """
---
TD_COAP_BLOCK_02:
    obj: Handle GET blockwise transfer for large resource (late negotiation)
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2-2.4'

    pre:
        - Client supports Block2 transfers
        - Server supports Block2 transfers
        - Server offers a large resource /large
        - Client does not know /large requires block transfer

    seq:
    -   s: "Client is requested to retrieve resource /large"

    -   c: Client sends a GET request not containing Block2 option

    -   c:
        - 'Server sends 2.05(Content) response with a Block2 option
        indicating:'
        -   - NUM = 0;
            - M = 1;
            - SZX = the proposed block size.
            - Payload size is 2SZX+4 bytes.

    -   c:
        - 'Client switches to blockwise transfer mode and sends a GET
        request with a Block2 option indicating:'
        -   - "NUM is the next block number(should be equal to
            2SZX_in_step_4 – SZX_in_step_3)"
            -    M = 0
            -    SZX is less or equals to SZX at step 3


    -   c:
        - 'Server sends 2.05(Content) response with a Block2 option
        indicating:'
        -   - NUM = k where “k” is the block number used at step 4
            - M = 1
            - SZX is the SZX at step 4
            - Payload size is 2SZX+4 bytes

    -   c:
        - 'Client sends GET request for further blocks indicating:'
        -   - 'NUM = i where “i” is the block number of the current block'
            - M = 0
            - SZX is the SZX at step 4

    -   c:
        - 'Server sends 2.05(Content) response with a Block2 option indicating:'
        -   - NUM = i where “i” is the block number used at step 6
            - M = 1
            - SZX is the SZX at step 4
            - Payload size is 2SZX+4 bytes

    -   c:
        -   'Client send GET request for the last block indicating:'
        -   - NUM = n where “n” is the last block number
            - M = 0
            - SZX is the SZX at step 4

    -   c:
        -   'Server sends 2.05(Content) response with a Block2 option
            indicating:'
        -   - NUM = n where “n” is the block number used at step 8
            - M = 0
            - SZX is the SZX at step 4
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
            CoAP(type='con', code='get', opt=Opt(CoAPOptionUriPath("large"), Not(CoAPOptionBlock())))
        ]

    def run(self):
        # Step 2 - initial request from the client
        self.match("client", CoAP(code = "get",
                         opt = self.uri("/large", NoOpt(CoAPOptionBlock2()))))

        self.next_skip_ack()

        # Step 3 - response from the server w/ block size negociation
        self.match("server", CoAP(code = 2.05,
                         opt = Opt(CoAPOptionBlock2(num=0))
                ), "fail")
        server_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]
        server_size = 2**(server_szx+4)

        # Step 3 - expect more blocks
        self.match("server", CoAP(opt = Opt(CoAPOptionBlock2(m=1)),
                         pl = Length(bytes, server_size)
                ))

        self.next_skip_ack()

        # Step 4 - second request from the client.
        self.match("client", CoAP(code = "get",
                         opt = Opt(CoAPOptionBlock2(szx=Range(int, 0, server_szx)))))

        client_szx  = self.coap["opt"][CoAPOptionBlock2]["szx"]
        client_size = 2**(client_szx+4)

        client_num  = self.coap["opt"][CoAPOptionBlock2]["num"]

        max_next_num = 2 **(server_szx - client_szx)
        if client_num > max_next_num:
            self.set_verdict("inconclusive", "discontinuity in client requests(next requested block should be between 1 and %d)" % max_next_num)

        for i in itertools.count(client_num):

            # Step 6,  Step 8 (last iteration)
            # request next block from client
            if self.match("client", CoAP(code = "get",
                             opt = Opt(CoAPOptionBlock2(num=i, szx=client_szx)))):

                self.match("client", CoAP(opt = Opt(CoAPOptionBlock2(m=0))), "fail")

            self.next_skip_ack()

            # Step 5 (first iteration), Step 7
            # send next block from server
            if not self.match("server", CoAP(code = 2.05,
                             opt = Opt(CoAPOptionBlock2(num=i, szx=client_szx))
                    )):
                break

            if not self.match("server", CoAP(opt = Opt(CoAPOptionBlock2(m=1)),
                                pl = Length(bytes, client_size)
                        ), None):
                # Step 9 - no more blocks
                self.match("server", CoAP(opt = Opt(CoAPOptionBlock2(m=0)),
                                pl = Length(bytes,(1, client_size))
                        ), "fail")

                # end of testcase
                self.next_skip_ack(optional = True)
                break

            self.next_skip_ack()
