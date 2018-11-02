import unittest
import os
import json
import logging

from ttproto.core.lib import ieee802154

from tests.test_tools.struct_validator import StructureValidator
from tests.test_dissector.test_dissect_pcaps import DissectPcapTestCase


class DissectorTestCase_802154(DissectPcapTestCase):
    """
    Test class for the dissector tool

    """

    # #################### Tests parameters #########################

    # File path
    PCAP_FILES_DISSECTION_DIRS = [
        'tests/test_dumps/802_15_4',
    ]
    PROTO_CLASS_FILTER = None
    TMP_DIR = 'tmp/'

    # Create a struct checker object
    struct_validator = StructureValidator()


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
