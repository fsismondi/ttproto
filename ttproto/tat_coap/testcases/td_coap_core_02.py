 #!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_02 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_02
Objective:
Perform DELETE transaction (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 5.8.4,1.2,2.1,2.2,3.1

Pre-test
conditions:
•	Server offers a /test resource that handles DELETE

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a DELETE request with:
•	Type = 0(CON)
•	Code = 4(DELETE)

2
Check
The request sent by the client contains:
•	Type=0 and Code=4
•	Client-generated Message ID (➔ CMID)
•	Client-generated Token (➔ CTOK)
•	Uri-Path option "test"

3
Check
Server sends response containing:
•	Code = 66(2.02 Deleted)
•	Message ID = CMID, Token = CTOK
•	Content-format option if payload non-empty
•	Empty or non-empty Payload

4
Verify
Client displays the received information
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
        return [CoAP(type='con', code='delete')]

    def run (self):
        self.match ("client", CoAP (type="con", code="delete",
                        opt=self.uri ("/test")))
        CMID = self.coap["mid"]
        CTOK = self.coap["tok"]

        self.next()

        self.match ("server", CoAP (code = 2.02, mid = CMID,tok=CTOK,))
        if self.match ("server", CoAP(pl = Not(b"")),None):
            self.match ("server", CoAP (
                        opt = Opt (CoAPOptionContentFormat()),
                ), "fail")

