#!/usr/bin/env python3

from ..common import *


class TD_COAP_CORE_31 (CoAPTestCase):
    """Identifier:
TD_COAP_CORE_31
Objective:
Perform CoAP Ping (CON mode)
Configuration:
CoAP_CFG_BASIC
References:
[COAP] 4.3

Pre-test
conditions:
(Should work with any CoAP server)

Test Sequence:
Step
Type
Description

1
Stimulus
Client is requested to send a "Ping" request with:
•	Type = 0 (CON)
•	Code = 0 (empty)

2
Check
The request sent by the client is four bytes and contains:
•	Type=0 and Code=0
•	Client-generated Message ID (➔ CMID)
•	Zero-length Token
•	No payload

3
Check
Server sends four-byte RST response containing:
•	Type=3 and Code=0
•	Message ID = CMID
•	Zero-length Token
•	No payload

4
Verify 	Client displays that the "Ping" was successful
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
            CoAP(type='con', code=0)  # Step 1
        ]

    def run (self):
        self.match ("client", CoAP (type="con", code = 0,tok=b"",pl=b""))
        CMID = self.coap["mid"]

        self.next_skip_ack()

        if self.match ("server", CoAP (type=3)):
            self.match ("server", CoAP (
                        code=0,
                        tok=b"",
                        pl=b"",
                    ), "fail")

