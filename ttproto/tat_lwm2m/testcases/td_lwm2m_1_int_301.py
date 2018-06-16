from ..common import *


class TD_LWM2M_1_INT_301(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_301
uri : http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: 
  - Sending the observation policy to the device
pre_conditions: 
  - The Client supports the Configuration C.4
  - Device is switched on and operational.
  - Client is registred with the LwM2M Server
notes: Please refer to TD_LWM2M_PRO.yaml file for more details
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'

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
        return [CoAP(type='con', code='get'), CoAP(type='con', code='put')]

    def run(self):
        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/6')), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/3/0/7')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionUriQuery('pmin=5'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionUriQuery('pmax=15'))), 'fail')

        self.next()

        self.match('client', CoAP(code=Any(65, 68)), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/3/0/8')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionUriQuery('pmin=10'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionUriQuery('pmax=20'))), 'fail')

        self.next()

        self.match('client', CoAP(code=Any(65, 68)), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/7')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionObserve('0'))))

        self.next()

        self.match('client', CoAP(code=2.05), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/3/0/8')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionObserve('0'))))

        self.next()

        self.match('client', CoAP(code=2.05), 'fail')

