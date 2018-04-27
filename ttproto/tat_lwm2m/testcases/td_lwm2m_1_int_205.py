from ..common import *


class TD_LWM2M_1_INT_205(CoAPTestCase):
    """
---
testcase_id: TD_LWM2M_1.0_INT_205
uri: http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
configuration: LWM2M_CFG_01
objective: Setting writable Resources of Server Object (ID:1) Instance 0 using Plain Text data format (0)
pre_conditions: 
  - The Client supports the configuration C.3 (A superset of C.1 where server objects implements {Default Minimum PEriod, Default Maximum Period, Disable Timeout} additional resources)  
  - The Client is supporting Plain Text data format (0)
  - Client is registred with the server
references: 'OMA-ETS-LightweightM2M-V1_0_1-20170926-A'
notes: This test case is composed by 48 steps. Please refer to TD_LWM2M_PRO.yaml file for more details.
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
        return [CoAP(type='con', code='put'), CoAP(type='con', code='get')]

    def run(self):
        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/2')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/3')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/5')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/2')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/3')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/5')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/2')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/3')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='put', opt=self.uri('/1/0/5')), 'fail')
        self.match('server', CoAP(pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('O'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=Any(65, 68), pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('0'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/2')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/3')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

        self.next()

        self.match('server', CoAP(type='con', code='get', opt=self.uri('/1/0/5')), 'fail')
        self.match('server', CoAP(pl=(b'')), 'fail')
        self.match('server', CoAP(opt=Opt(CoAPOptionAccept('11542'))), 'fail')
        
        self.next()

        self.match('client', CoAP(code=2.05, pl=Not(b'')), 'fail')
        self.match('client', CoAP(opt=Opt(CoAPOptionContentFormat('11542'))), 'fail')

