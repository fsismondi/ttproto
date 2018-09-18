from ..common import *


class TD_LWM2M_1_INT_220(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_220
uri: http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Setting the writable resources of object 1 (Server Object_ID 1) Instance 0 in using JSON data format (11543) and restoring these resources to their initial values
  - This test has to be run for the following resources
  - - Default Minimum Period
  - - Default maximum Period
  - - Disable Timeout
  - - Notification Storing When Disabled or Offline
  - - Binding
pre_conditions: 
  - Device is registred with the Server
  - The current values of the Server Object (ID:1) Instance 0, are saved on the Server
  - The Client supports the Configuration C.3 (A superset of C.1 where server objects implements {Default Minimum PEriod, Default Maximum Period, Disable Timeout} additional resources)  
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_220_step_01'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a WRITE request (CoAP PUT) on server object instance'
      - - Type = 0 (CON)
        - Code = 3 (PUT)

  - step_id: 'TD_LWM2M_1.0_INT_220_step_02'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=3
        - Non-empty payload = array of Default Minimum Period, Default Maximum Period, Disable Timeout, Notification Storing When Disabled or offline, and Binding resource values
        - content-format=application/vnd.oma.lwm2m+json
        - URI-Path option= 1/0

  - step_id: 'TD_LWM2M_1.0_INT_220_step_03'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.04 (Changed)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload= A serialized representation of Default Minimum Period, Default Maximum Period, Disable Timeout, Notification Storing When Disabled or offline, and Binding resource values

  - step_id: 'TD_LWM2M_1.0_INT_220_step_04'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'

  - step_id: 'TD_LWM2M_1.0_INT_220_step_05'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a READ request (CoAP GET) on server object instance'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_LWM2M_1.0_INT_220_step_06'
    type: check
    description:
      - 'Sent GET request contains'
      - - Type=0 and Code=1
        - Accept option=application/vnd.oma.lwm2m+json
        - URI-Path option= 1/0

  - step_id: 'TD_LWM2M_1.0_INT_220_step_07'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.05 (Content)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload
          - A serialized representation of server object instance with Default Minimum Period, Default Maximum Period, Disable Timeout, Notification Storing When Disabled or offline, and Binding resource values
          - The received values are consistent with the 220-SetOfValues sample

  - step_id: 'TD_LWM2M_1.0_INT_220_step_08'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'

  - step_id: 'TD_LWM2M_1.0_INT_220_step_09'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a WRITE request (CoAP POST) on server object instance'
      - - Type = 0 (CON)
        - Code = 3 (PUT)

  - step_id: 'TD_LWM2M_1.0_INT_220_step_10'
    type: check
    description:
      - 'Sent PUT request contains'
      - - Type=0 and Code=3
        - Non-empty payload = array of initial values (which have been preserved) of Minimum Period, Default Maximum Period, Disable Timeout, Notification Storing When Disabled or offline, and Binding resources
        - content-format=application/vnd.oma.lwm2m+json
        - URI-Path option= 1/0

  - step_id: 'TD_LWM2M_1.0_INT_220_step_11'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.04 (Changed)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload

  - step_id: 'TD_LWM2M_1.0_INT_220_step_12'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'

  - step_id: 'TD_LWM2M_1.0_INT_220_step_13'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a READ request (CoAP GET) on server object instance'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_LWM2M_1.0_INT_220_step_14'
    type: check
    description:
      - 'Sent GET request contains'
      - - Type=0 and Code=1
        - Accept option=application/vnd.oma.lwm2m+json
        - URI-Path option= 1/0

  - step_id: 'TD_LWM2M_1.0_INT_220_step_15'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.05 (Content)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload
          - A serialized representation of server object instance with Default Minimum Period, Default Maximum Period, Disable Timeout, Notification Storing When Disabled or offline, and Binding resource values
          - The received values are consistent with the values present in the initial configuration 3.

  - step_id: 'TD_LWM2M_1.0_INT_220_step_16'
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
        return [CoAP(type='con', code='put'), CoAP(type='con', code='get'), CoAP(type='con', code='put')]

    def run(self):
        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        validation = validate(str(self.coap['pl']),'1')
        self.set_verdict(validation[0], validation[1])

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        validation = validate(str(self.coap['pl']),'1')
        self.set_verdict(validation[0], validation[1])
