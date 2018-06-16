from ..common import *


class TD_IPSO_3302_05(CoAPTestCase):
    """
testcase_id: TD_IPSO_3302_05 
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m 
configuration: LWM2M_CFG_01 
objective: Delete an Instance of Presence Object
pre_conditions:
  - Device is registred with the Server
  - The current values of the Server Object (ID:1) Instance 0, are saved on the Server
  - The Client supports the Configuration C.3 (A superset of C.1 where server objects implements {Default Minimum PEriod, Default Maximum Period, Disable Timeout} additional resources)  
  - - LWM2M Server Object (ID = 1) Instance 0 with mandatory resources and Short Server ID = 1
  - - LWM2M Security Object (ID = 0) Instance 0 with mandatory resources and Bootstrap Server = False
  - - LWM2M Device Object (ID = 3) Instance 0 with mandatory resources. 
  - The Client supports IPSO Presence object (ID:3302) with mandatory resources. 
sequence:
  - step_id: 'TD_IPSO_3302_05_step_01'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a DELETE request (CoAP Delete) on Presence object instance'
      - - Type = 0 (CON)
        - Code = 4 (DELETE)

  - step_id: 'TD_IPSO_3302_05_step_02'
    type: check
    description:
      - 'Sent DELETE request contains'
      - - Type=0 and Code=4
        - empty payload
        - URI-Path option= Location of the Presence object instance to delete 

  - step_id: 'TD_IPSO_3302_05_step_03'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.02 (Deleted)
        - empty payload. 

  - step_id: 'TD_IPSO_3302_05_step_04'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'
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

    def run(self):
        self.match('server', CoAP(type='con', code='delete', opt=self.uri()), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')       

        self.next()

        self.match('client', CoAP(code=2.02), 'fail')
        self.match('client', CoAP(pl=(b'')), 'fail')

                
