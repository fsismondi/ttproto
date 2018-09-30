import os

from tests.test_tat.test_tat import TestAnalysisInteropTestCase


class TestAnalysisInteropCoreTestCase(TestAnalysisInteropTestCase):

    def setUp(self):
        pass
        self.pcap_dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../test_dumps/coap_core')
        self.pcap_path_list = os.listdir(self.pcap_dir_path)
