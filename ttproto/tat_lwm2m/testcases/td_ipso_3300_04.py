from ..common import *


class TD_IPSO_3300_04(CoAPTestCase):
    """
testcase_id: TD_IPSO_3300_04 
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m 
configuration: LWM2M_CFG_01 
objective: Creating a new Instance of the Generic Sensor Object in JSON format
pre_conditions:
  - Device is registred with the Server
  - The current values of the Server Object (ID:1) Instance 0, are saved on the Server
  - The Client supports the Configuration C.3 (A superset of C.1 where server objects implements {Default Minimum PEriod, Default Maximum Period, Disable Timeout} additional resources)  
  - - LWM2M Server Object (ID = 1) Instance 0 with mandatory resources and Short Server ID = 1
  - - LWM2M Security Object (ID = 0) Instance 0 with mandatory resources and Bootstrap Server = False
  - - LWM2M Device Object (ID = 3) Instance 0 with mandatory resources. 
  - The Client supports IPSO Generic Sensor (ID:3300) with mandatory resources. 
sequence:
  - step_id: 'TD_IPSO_3300_04_step_01'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a CREATE request (CoAP POST) on Generic Sensor object'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_IPSO_3300_04_step_02'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Non-empty payload = The representation of new Device object instance
        - content-format=application/vnd.oma.lwm2m+json
        - URI-Path option= /3300

  - step_id: 'TD_IPSO_3300_04_step_03'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.04 (Changed)
        - Location-Path option= the location of the created instance (LP)

  - step_id: 'TD_IPSO_3300_04_step_04'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'

  - step_id: 'TD_IPSO_3300_04_step_05'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a READ request (CoAP GET) on new Generic Sensor object'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_IPSO_3300_04_step_06'
    type: check
    description:
      - 'Sent GET request contains'
      - - Type=0 and Code=1
        - Accept option=application/vnd.oma.lwm2m+json
        - URI-Path option= LP

  - step_id: 'TD_IPSO_3300_04_step_07'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.05 (Content)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload = A serialized representation of new instance 

  - step_id: 'TD_IPSO_3300_04_step_08'
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
        return [CoAP(type='con', code='post'), CoAP(type='con', code='get')]

    def run(self):
        self.match('server', CoAP(type='con', code='post', pl=Not(b''), opt=self.uri('/3300')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        

        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')

        OPTS = self.coap['opt']
        LP = OPTS[CoAPOptionLocationPath]
        LPVAL = RI[2]

        self.next()
        
    
        self.match('server', CoAP(type='con', code='get', pl=(b''), opt=self.uri(LPVAL)), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        
        validation = validate(str(self.coap['pl']),'3300')
        self.set_verdict(validation[0], validation[1])

