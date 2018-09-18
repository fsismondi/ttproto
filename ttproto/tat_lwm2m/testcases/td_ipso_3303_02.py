from ..common import *


class TD_IPSO_3303_02(CoAPTestCase):
    """
testcase_id: TD_IPSO_3303_02 
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m 
configuration: LWM2M_CFG_01 
objective: Creating a new Instance of the Temperature Object in JSON format
pre_conditions:
  - Device is registred with the Server
  - The current values of the Server Object (ID:1) Instance 0, are saved on the Server
  - The Client supports the Configuration C.3 (A superset of C.1 where server objects implements {Default Minimum PEriod, Default Maximum Period, Disable Timeout} additional resources)  
  - - LWM2M Server Object (ID = 1) Instance 0 with mandatory resources and Short Server ID = 1
  - - LWM2M Security Object (ID = 0) Instance 0 with mandatory resources and Bootstrap Server = False
  - - LWM2M Device Object (ID = 3) Instance 0 with mandatory resources. 
  - The Client supports IPSO Temperature object (ID:3302) with mandatory resources. 
sequence:
  - step_id: 'TD_IPSO_3303_02_step_01'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a CREATE request (CoAP POST) on Temperature object'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_IPSO_3303_02_step_02'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Non-empty payload = The representation of new Temperature object instance
        - content-format=application/vnd.oma.lwm2m+json
        - URI-Path option= /3303

  - step_id: 'TD_IPSO_3303_02_step_03'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.04 (Changed)
        - Location-Path option= the location of the created instance

  - step_id: 'TD_IPSO_3303_02_step_04'
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
        return [CoAP(type='con', code='post')]

    def run(self):
        self.match('server', CoAP(type='con', code='post', pl=Not(b''), opt=self.uri('/3303')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        

        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')
