import os

from tests.test_tat.test_tat import TestAnalysisInteropTestCase


class TestAnalysisInteropObserveTestCase(TestAnalysisInteropTestCase):

    def setUp(self):
        pass
        self.pcap_dir_path = os.path.dirname(os.path.abspath(__file__))
        self.pcap_dir_path = os.path.join(self.pcap_dir_path, '../test_dumps/dissection/coap/coap_observe')
        self.pcap_path_list = os.listdir(self.pcap_dir_path)
