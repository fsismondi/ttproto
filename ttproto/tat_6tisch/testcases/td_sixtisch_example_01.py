#!/usr/bin/env python3

from ttproto.tat_6tisch.common import *

"""
NOTE

for each TC class you must either
-include:

    Objective:
    Description of the purpose of the test

- overwrite method get_test_purpose method
"""

class TD_SIXTISCH_EXAMPLE_01 (SixTischTestCase):
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



    def run (self):
        # analyse sth and then emit a verdict, note if using match then the verdict should be updated using verdict param
        self.set_verdict('pass', 'I am the walrus!')
