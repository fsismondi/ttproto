from ..common import *


class TD_LWM2M_1_INT_104(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_104
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: Test that the Client updates its registration with the Server when triggered with the Registration Update Trigger.
pre_conditions:
  - Device is turned on. 
  - The bootstarp procedure has been completed or the required bootstarp information is available to the client.
  - The device is registred with the Server with a Lifetime of 20s. 
  - The Client supports the minimum Configuration C.1.
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_104_step_01'
    type: stimuli
    node : lwm2m_server
    description:
      - 'Lwm2m server is requested to send Registration Update Tigger message (CoAP POST) to client'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_104_step_02'
    type: check
    description:
      - 'The request sent by the server contains'
      - - Type=0 and Code=2
        - Uri-Path option= 1/0/8

  - step_id: 'TD_LWM2M_1.0_INT_104_step_03'
    type: check
    description:
        - 'Lwm2m client sends response containing'
        - - Code = 2.04 (Changed)

  - step_id: 'TD_LWM2M_1.0_INT_104_step_04'
    type: verify
    node: lwm2m_server
    description:
        - 'Server receives a Success message'

  - step_id: 'TD_LWM2M_1.0_INT_104_step_05'
    type: stimuli
    node : lwm2m_client
    description:
      - 'LwM2M Client is requested to send an UPDATE Registration message without parameter (CoAP POST) to server'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_104_step_06'
    type: check
    description:
        - 'The request sent by the client contains'
        - - Type=0 and Code=2
          - Uri-Path option= /rd

  - step_id: 'TD_LWM2M_1.0_INT_104_step_07'
    type: check
    description:
        - 'Server sends response containing'
        - - Code = 2.04 (Changed)

  - step_id: 'TD_LWM2M_1.0_INT_104_step_08'
    type: verify
    node: lwm2m_client
    description:
        - 'Client has received Success message from Server'
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
        return [CoAP(type='con', code='post')]

    def run(self):
        self.match('server', CoAP(type='con', code='post', opt=self.uri('/1/0/8')), 'fail')
        self.match('server', CoAP(pl=(b'')))
        
        self.next()

        self.match('client', CoAP(type='con', code=Any(65, 68)), 'fail')
    
        self.next()

        self.match('client', CoAP(type='con', code='post', opt=self.uri('/rd')), 'fail')
  
        self.next()

        self.match('server', CoAP(type='con', code=Any(65,68)), 'fail')
