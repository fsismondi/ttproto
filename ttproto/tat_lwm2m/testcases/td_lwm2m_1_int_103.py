from ..common import *


class TD_LWM2M_1_INT_103(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_103
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: Test that the Client is able to deregister at the server.
pre_conditions:
  - Client is registred with the server
  - The Client supports the minimum Configuration C.1.
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_103_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'LwM2M Server is requested to send EXECUTE command (COAP POST) on the Disable Resource of the Server Object (ID:1) Instance'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_103_step_02'
    type: check
    description:
      - 'The request sent by the lwm2m server contains'
      - - Type=0 and Code=2
        - Uri-Path option = 1/0/4


  - step_id: 'TD_LWM2M_1.0_INT_103_step_03'
    type: check
    description:
        - 'Lwm2m client sends response containing'
        - - Code = 2.04(Changed)

  - step_id: 'TD_LWM2M_1.0_INT_103_step_04'
    type: verify
    node: lwm2m_server
    description:
        - 'The lwm2m server receives the Sucess Message'

  - step_id: 'TD_LWM2M_1.0_INT_103_step_05'
    type: stimuli
    node : lwm2m_client
    description:
      - 'Client is requested to send a de-regestration (COAP DELETE) to Server'
      - - Type = 0 (CON)
        - Code = 4 (DELETE)

  - step_id: 'TD_LWM2M_1.0_INT_103_step_06'
    type: check
    description:
      - 'The request sent by the client contains'
      - - Type=0 and Code=4
        - Uri-Path = the location of the created registration


  - step_id: 'TD_LWM2M_1.0_INT_103_step_07'
    type: check
    description:
        - 'Server sends response containing'
        - - Code = 2.02(Deleted)

  - step_id: 'TD_LWM2M_1.0_INT_103_step_08'
    type: verify
    node: lwm2m_client
    description:
        - 'Client receives Success Message from the server'
        - 'Client is removed from the servers registration database'
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
        return [CoAP(type='con', code='post'), CoAP(type='con', code='delete')]

    def run(self):
        self.match('server', CoAP(type='con', code='post', opt=self.uri('/1/0/4')), 'fail')

        self.next()

        self.match('client', CoAP(type='con', code=Any(65, 68)), 'fail')
    
        self.next()

        self.match('client', CoAP(type='con', code='delete', opt=self.uri()), 'fail')
  
        self.next()

        self.match('server', CoAP(type='con', code=2.02, pl=(b'')), 'fail')

