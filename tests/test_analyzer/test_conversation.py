import unittest

from ttproto.core.analyzer import Conversation, Node
from ttproto.core.data import Value
from ttproto.core.typecheck3000 import InputParameterError
from ttproto.core.lib.all import *


class ConversationTestCase(unittest.TestCase):
    """
    Test class for the Conversation class
    """

    # #################### Tests parameters #########################

    # The nodes used here (CoAP ones)
    NODES = [Node('client', UDP(dport=5683)), Node('server', UDP(sport=5683))]

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the conversation instance
        """
        self.conversation = Conversation(self.NODES)

    # #################### Tests functions #########################

    # ##### __init__
    def test___init__single_node_not_a_list(self):
        with self.assertRaises(InputParameterError):
            self.conversation = Conversation(self.NODES[0])

    def test___init__single_node_in_a_list(self):
        with self.assertRaises(ValueError):
            self.conversation = Conversation([self.NODES[0]])

    def test___init__empty_list(self):
        with self.assertRaises(ValueError):
            self.conversation = Conversation([])

    # ##### nodes
    def test_nodes(self):

        # Get and check nodes
        nodes = self.conversation.nodes
        self.assertIsInstance(nodes, dict)
        self.assertEqual(len(nodes), 2)
        for node_name, node_value in nodes.items():
            self.assertIsInstance(node_name, str)
            self.assertIsInstance(node_value, Value)

        # Check that setting it is blocked
        with self.assertRaises(AttributeError):
            self.conversation.nodes = nodes

    # ##### __bool__
    def test___bool__(self):
        self.assertTrue(self.conversation)


# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
