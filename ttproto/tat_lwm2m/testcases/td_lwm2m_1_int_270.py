from ..common import *


class TD_LWM2M_1_INT_270(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_270 
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m 
configuration: LWM2M_CFG_01 
objective: Creating a new Instance of the Device Object 
pre_conditions:
  - The Client supports the minimum configuration C.1
  - The Client is registred with the Server
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
sequence:
  - step_id: 'TD_LWM2M_1.0_INT_270_step_01'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a CREATE request (CoAP POST) on Device object'
      - - Type = 0 (CON)
        - Code = 2 (POST)

  - step_id: 'TD_LWM2M_1.0_INT_270_step_02'
    type: check
    description:
      - 'Sent POST request contains'
      - - Type=0 and Code=2
        - Non-empty payload = The representation of new Device object instance
        - content-format=application/vnd.oma.lwm2m+json
        - URI-Path option= /3

  - step_id: 'TD_LWM2M_1.0_INT_270_step_03'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.04 (Changed)
        - content-format=application/vnd.oma.lwm2m+json
        - Location-Path option= the location of the created instance (LP)
        - Non-empty payload= A serialized representation of the created Device object instance

  - step_id: 'TD_LWM2M_1.0_INT_270_step_04'
    type: verify
    node: lwm2m_server
    description:
      - 'LwM2M server indicates successful operation'

  - step_id: 'TD_LWM2M_1.0_INT_270_step_05'
    type: stimuli
    node: lwm2m_server
    description:
      - 'LwM2M server sends a READ request (CoAP GET) on device object'
      - - Type = 0 (CON)
        - Code = 1 (GET)

  - step_id: 'TD_LWM2M_1.0_INT_270_step_06'
    type: check
    description:
      - 'Sent GET request contains'
      - - Type=0 and Code=1
        - Accept option=application/vnd.oma.lwm2m+json
        - URI-Path option= LP

  - step_id: 'TD_LWM2M_1.0_INT_270_step_07'
    type: check
    description:
      - 'LwM2M client sends response containing'
      - - Code = 2.05 (Content)
        - content-format=application/vnd.oma.lwm2m+json
        - Non-empty payload = An array of device object resources

  - step_id: 'TD_LWM2M_1.0_INT_270_step_08'
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
        self.match('server', CoAP(type='con', code='post', pl=Not(b''), opt=self.uri('/1')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')

        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionLocationPath())), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', pl=(b''), opt=self.uri()), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11543'))), 'fail')

        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11543'))), 'fail')

        validation = validate(str(self.coap['pl']), '1')
        self.set_verdict(validation[0], validation[1])
