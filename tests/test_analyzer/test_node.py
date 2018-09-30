import unittest

from ttproto.core.analyzer import Node
from ttproto.core.data import Value
from ttproto.core.typecheck3000 import InputParameterError
from ttproto.core.lib.all import *


class NodeTestCase(unittest.TestCase):
    """
    Test class for the node class
    """

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the analyzer instance
        """
        self.node = Node('name', UDP(sport=5683))

    # #################### Tests functions #########################

    # ##### __init__
    def test___init__(self):

        # Normal use
        self.node = Node('name', UDP(sport=5683))

        # Wrong name
        with self.assertRaises(InputParameterError):
            self.node = Node(IPv4(src='127.0.0.1'), UDP(sport=5683))

        # Wrong value
        with self.assertRaises(InputParameterError):
            self.node = Node('name', '127.0.0.1')

    # ##### name
    def test_name(self):

        # Get name
        name = self.node.name
        self.assertIsInstance(name, str)

        # Set name
        with self.assertRaises(AttributeError):
            self.node.name = name

    # ##### value
    def test_value(self):

        # Get value
        value = self.node.value
        self.assertIsInstance(value, Value)

        # Set value
        with self.assertRaises(AttributeError):
            self.node.value = value


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
