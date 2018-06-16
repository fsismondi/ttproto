from ..common import *


class TD_LWM2M_1_INT_102(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_102
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: Test that the Client updates the registration information on the server.
pre_conditions:
  - The Client supports the minimum Configuration C.1.
  - Client is registred with the Server
  - The Server will be prepared to change the client lifetime registration to 20 sec to set the conditions for a Client UPDATE  operation
  - On option, the client will be prepared to update its registration before the registration time expires
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_102_step_01'
    type: stimuli
    node : lwm2m_client
    description:
      - 'Client is requested a WRITE request (COAP PUT) to Server to set lifetime resource of the Server Object Instance to 20 sec'
      - - Type = 0 (CON)
        - Code = 3 (PUT)

  - step_id: 'TD_LWM2M_1.0_INT_102_step_02'
    type: check
    description:
      - 'The request sent by the client contains'
      - - Type=0 and Code=3
        - Non-empty payload= A Media-Type payload where each Object is described as a Link according to content-format option. 
        - content-format=text/plain
        - Uri-Path option = 1/0/1

  - step_id: 'TD_LWM2M_1.0_INT_102_step_03'
    type: check
    description:
      - 'LwM2M server sends response containing'
      - - Code = 2.04 (Changed)
        - content-format=text/plain
        - Non-empty payload

  - step_id: 'TD_LWM2M_1.0_INT_102_step_04'
    type: verify
    node: lwm2m_client
    description:
      - 'LwM2M client indicates successful operation'

  - step_id: 'TD_LWM2M_1.0_INT_102_step_05'
    type: stimuli 
    node: lwm2m_client
    description:
      - 'LwM2M client sends a Re-registration message (CoAP POST) to LwM2M server'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_102_step_06'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Uri-Path option = the location of the created registration
        - Uri-Query option = 'lt={20}'

  - step_id: 'TD_LWM2M_1.0_INT_102_step_07'
    type: check
    description:
      - 'LwM2M server sends response containing'
      - - Code = 2.04 (Changed)

  - step_id: 'TD_LWM2M_1.0_INT_102_step_08'
    type: verify
    node: lwm2m_client
    description:
      - 'LwM2M client indicates successful operation'
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
        return [CoAP(type='con', code='put'), CoAP(type='con', code='post')]

    def run(self):
        self.match('client', CoAP(type='con', code='put', opt=self.uri('/1/0/1')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('40'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionAccept('0'))), 'fail')
        self.next()

        self.match('server', CoAP(type='con', code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('client', CoAP(type='con', code='post', opt=self.uri()), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionUriQuery('lt=20'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code=Any(65, 68)), 'fail')

