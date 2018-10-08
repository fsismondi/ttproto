from ..common import *


class TD_COAP_CORE_32(CoAPTestCase):
    @classmethod
    @typecheck
    def get_stimulis(cls) -> list_of(Value):
        """
        This is just a dummy test case used for testing stuff.

        Get the stimulis of this test case. This has to be be implemented into
        each test cases class.

        :return: The stimulis of this TC
        :rtype: [Value]
        """
        return [CoAP(type='con', code='get')]

    def run(self):
        if self.match('client', CoAP(type='con', code='get', opt=self.uri('/'))):
            self.match('client', CoAP(type='con', code='get', opt=Opt(CoAPOptionOneM2MFrom())), 'fail')

        CMID = self.coap['mid']
        CTOK = self.coap['tok']

        self.next()

        if self.match('server', CoAP(code=2.05, mid=CMID, tok=CTOK, pl=Not(b'')), 'fail'):
            self.match('server', CoAP(opt=Opt(CoAPOptionContentFormat())), 'fail')
