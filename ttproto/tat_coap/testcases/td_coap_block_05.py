from ..common import *
from ...core.templates import Range

class TD_COAP_BLOCK_05 (CoAPTestCase):
    """
---
TD_COAP_BLOCK_05:
    obj: Handle POST with two-way blockwise transfer
    cfg: CoAP_CFG_BASIC
    ref: '[BLOCK] 2.2, 2.3, 2.5'

    pre:
        - Client supports Block1 and Block2 transfers
        - Server supports Block1 and Block2 transfers
        - "Server accepts large post requests on /large-post"

    seq:
    -   s: "Client is requested to send a large represenation to /large-post on Server"

    -   c:
    - 'Client sends a POST request containing Block1 option indicating:'
    -   - NUM = 0
        - M = 1 (more)
        - "SZX (➔DES_SZX) is the desired block size"
        - "Payload size is 2**(SZX+4) bytes"

    -   c:
        - 'Server sends 2.31 (Continue) response containing Block1 option indicating:'
        -   - NUM = 0
            - M = 1 (atomic)
            - "SZX (➔ACT_SZX) is less or equal to DES_SZX"

    -   c:
        - 'Client sends further POST requests containing Block1 option indicating:'
        -   - 'NUM = i where “i” is the block number of the current block.
            If the server decreased the SZX parameter in step 3,
            then the client needs to adapt the block size accordingly
            and resumes the transfer from block number 2**(DES_SZX - ACT_SZX)
            instead of block 1.'
            - M = 1 (more)
            - SZX is ACT_SZX
            - "Payload size is 2**(SZX+4) bytes"

    -   c:
        - 'Server sends 2.31 (Continue) response containing Block1 option indicating:'
        -   - NUM = i where “i” is the block number used at step 4
            - M = 1 (atomic)
            - SZX is ACT_SZX

    -   c:
        - 'Client sends POST request containing the last block and indicating:'
        -   - NUM = n where “n” is the last block number
            - M = 0 (final)
            - SZX is ACT_SZX
            - 'Payload size is less than or equal to 2**(SZX+4) bytes.'

    -   c:
        - 'Server sends 2.04 (Changed) response containing Block1 option indicating:'
        -   - NUM = n where “n” is the block number used at step 6
            - M = 0 (final)
            - SZX is ACT_SZX
        - 'and a Block2 option indicating:'
        -   - NUM = 0
            - M = 1 (more)
            - 'SZX (➔rDES_SZX) is the desired block size'
            - 'Payload size is 2**(SZX+4) bytes'

    -   c:
        - 'Client switches to blockwise retrieval of response
        and sends a POST request, with the same options except for Block1,
        without payload, with a Block2 option indicating:'
        -   - 'NUM is the next block number k = (2**(rDES_SZX – rACT_SZX))'
            - M = 0
            - "SZX (➔rACT_SZX) is less than or equal to rDES_SZX"

    -   c:
        - "Server sends 2.04 (Changed) response with a Block2 option indicating:"
        -   - NUM = k where “k” is the block number used at step 8
            - M = 1
            - SZX is rACT_SZX
            - 'Payload size is 2**(SZX+4) bytes'

    -   c:
        - 'Client sends a similar POST request for retrieving a further block
        indicating:'
        -   - NUM = i where “i” is the block number of the current block
            - M = 0
            - SZX is rACT_SZX

    -   c:
        - 'Server sends 2.04 (Changed) response with a Block2 option indicating:'
        -   - NUM = i where “i” is the block number used at step 10
            - M = 1
            - SZX is rACT_SZX
            - 'Payload size is 2**(SZX+4) bytes'

    -   c:
        - 'Client sends another POST request (which will retrieve the last block)
            indicating:'
        -   -NUM = n where “n” is the last block number
            - M = 0
            - SZX is rACT_SZX.

    -   c:
        - 'Server sends 2.04 (Changed) response with a Block2 option indicating:'
        -   - NUM = n where “n” is the block number used at step 12
            - M = 0
            - SZX is rACT_SZX
            - Payload size is less than or equal to 2**(SZX+4) bytes

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
        """
        return [
            CoAP(type='con', code='post', opt=Opt(CoAPOptionUriPath("large-post"))),
        ]

    def run (self):
        # Step 2
        self.match("client",CoAP(type="con",code="post",opt=self.uri("/large-post", CoAPOptionBlock1(num=0, m=1))))
        client_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
        client_size = 2**(client_szx+4)
        self.match("client", CoAP (pl = Length(bytes, client_size)), "fail")

        self.next()
        # Step 3
        if self.match("server",CoAP(type="ack",code=2.31,opt=Opt(CoAPOptionBlock1(num=0,m=1)))):
            if not self.match("server", CoAP (opt = Opt (CoAPOptionBlock1 (szx=Range(int, 0, client_szx))))):
                raise self.Stop()
            server_szx  = self.coap["opt"][CoAPOptionBlock1]["szx"]
            server_size = 2**(server_szx+4)
            self.next()
            j=1
            while 1 :
                # Step 4
                self.match("client",CoAP(type="con",code="post",opt=Opt(CoAPOptionBlock1(num=j,szx=server_szx))),"fail")
                self.next()
                # Step 5
                self.match("server",CoAP(type="ack",opt=Opt(CoAPOptionBlock1(num=j))),"fail")
                # Step 6
                if not self.match("server",CoAP(code=2.31,opt=Opt(CoAPOptionBlock1(m=1))),None):
                    break
                self.next()
                j+=1
            # Step 7
            if self.match("server",CoAP(code=2.04,opt=Opt(CoAPOptionBlock1(m=0),CoAPOptionBlock2(num=0,m=1)))) :
                self.next()
                j=1
                while 1 :
                    # Step 8
                    self.match("client",CoAP(type="con",code="post",opt=Opt(CoAPOptionBlock2(num=j,m=0))),"fail")
                    self.next()
                    # Step 9
                    self.match("server",CoAP(type="ack",code=2.04, opt=Opt(CoAPOptionBlock2(num=j))),"fail")
                    # Step 10
                    if not self.match("server",CoAP(opt=Opt(CoAPOptionBlock2(m=1))),None):
                        break
                    self.next()
                    j+=1
        raise self.Stop()
