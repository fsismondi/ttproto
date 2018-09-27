from ..common import *
from ...core.templates import Range

class TD_COAP_BLOCK_04(CoAPTestCase):
    """
---
TD_COAP_BLOCK_04:
    obj: Handle POST blockwise transfer for large resource
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2, 2.3, 2.5'

    pre:
        - Client supports Block1 transfers
        - Server supports Block1 transfers
        - Server accepts creation of new resources on /large-create

    seq:
    -   s: 'Client is requested to create a new resource /large-create on
        Server'

    -   c:
        - 'Client sends a POST request containing Block1 option
        indicating:'
        -   - NUM = 0
            - M = 1
            - SZX = the desired block size
            - Payload size is 2SZX+4 bytes

    -   c:
        - 'Server sends 2.31 (Continue) response containing Block1 option indicating:'
        -   - NUM = 0
            - M = 1 (atomic)
            - SZX is less or equal to the SZX at step 2

    -   c:
        - 'Client sends further requests containing Block1 option indicating:'
        -   - 'NUM = i where “i” is the block number of the current
            block. If the server decreased the SZX parameter in
            step 3, then the client should adapt the block size
            accordingly and may resume the transfer from block
            id 2size_in_step_2-size_in_step_3 instead of block 1)'
            - M = 1 (more)
            - SZX is the SZX at step 3
            - "Payload size is 2SZX+4 bytes"

    -   c:
        - 'Server sends 2.01 (Created) response containing
        Block1 option indicating:'
        -   - NUM = i where “i” is the block number used at step 4
            - M = 1 (atomic)
            - SZX is the SZX at step 3

    -   c:
        - 'Client send PUT request containing the last block and
        indicating:'
        -   - NUM = n where “n” is the last block number;
            - M = 0 (final)
            - SZX is the SZX at step 3
            - Payload size is lesser or equal to 2SZX+4

    -   c:
        - 'Server sends 2.01 (Created) response containing Block1
        option indicating:'
        -   - NUM = n where “n” is the block number used at step 6
            - M = 0
            - SZX is the SZX at step 3
        - 'and Location-Path options, e.g. if the new location
            is "/large-create/PS":'
        -   - First option value must contain “large-create”
            - Second option value is a (single) path segment chosen by the server (PS)
            - none of the Location-Path options contain a ‘/’

    -   v: Client displays the response

    -   v: 'Server indicates presence of the complete new resource,
            e.g., /large-create/PS'

    -   c:
        - 'Client sends GET request to new location (e.g., "/large-create/PS",
            i.e., using Uri-Path options simply copied from the Location-Path
            of step 7)'

    -   c: 'Server sends 2.05 (Content) response with representation
            of created resource, potentially making use of the Block2 protocol'

    -   v: Client indicates the value of the newly created resource

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
            CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("large-create"))),
        ]

    def run (self):
        # Step 2 - initial request from the client
        self.match("client", CoAP (code = "post",
                         opt = self.uri ("/large-create", CoAPOptionBlock1 (num=0, m=1))))
        client_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
        client_size = 2**(client_szx+4)
        self.match("client", CoAP (pl = Length (bytes, client_size)), "fail")

        self.next_skip_ack()

        # Step 3 - response from the server possibly w/ block size negociation
        if not self.match("server", CoAP (code = 2.31,
                         opt = Opt (CoAPOptionBlock1 (num=0,m=1, szx=Range(int, 0, client_szx)))
                )):
            return
        server_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
        server_size = 2**(server_szx+4)

        self.next_skip_ack()

        # next block should have num 1
        counter = itertools.count (1)

        if server_szx != client_szx:
            # client & server do not agree on the block size

            # server requested a smaller block size, num may be bigger
            if (self.match("client", CoAP (opt = Opt (CoAPOptionBlock1()))), None):
                num = self.coap["opt"][CoAPOptionBlock1]
                if num > 1:
                    counter = itertools.count (num)

        for i in counter:

            # Step 4 - send next block from client
            self.match("client", CoAP (code = "post",
                             opt = Opt (CoAPOptionBlock1(num=i, szx=server_szx))
                    ))

            # Step 4 - more blocks.
            last = not self.match("client", CoAP (    opt = Opt (CoAPOptionBlock1(m=1)),
                                    pl = Length (bytes, server_size)
                    ), None)
            if last:
                # Step 6 - last block
                self.match("client", CoAP (    opt = Opt (CoAPOptionBlock1 (m=0)),
                                    pl = Length (bytes, (1, server_size))
                        ), "fail")

            self.next_skip_ack()

            # Step 5/Step 7 - ack from the server
            if not self.match("server", CoAP (code = Any (CoAPCode (2.01), 2.31),
                             opt = Opt (CoAPOptionBlock1(num=i, szx=server_szx))
                    )):
                raise self.Stop()

            if last:
                # Step 7
                if not self.match("server",CoAP(opt=self.uri ("/large-create",
                        CoAPOptionBlock1 (m=0),
                        CoAPOptionLocationPath(),
                        CoAPOptionLocationPath()
                    )),"fail"):
                    raise self.Stop()
                break
            self.next_skip_ack (optional = True)
        # LocationPath value
        for o in self.coap["opt"]:
            if CoAPOptionLocationPath(dlt=0).match(o):
                valPath=o["val"]
        self.next(optional = True)
        # Step 10
        if self.match("client",CoAP(code="get",opt=self.uri ("/large-create/"+valPath,CoAPOptionUriPath(),CoAPOptionUriPath(valPath))),None):
            self.next_skip_ack ()
            # Step 11
            self.match("server",CoAP(code=2.05,opt=Opt(CoAPOptionBlock2())))
        raise self.Stop()
