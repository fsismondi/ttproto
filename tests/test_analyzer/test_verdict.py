import unittest

from ttproto.core.analyzer import Verdict
from ttproto.core.typecheck3000 import InputParameterError


class VerdictTestCase(unittest.TestCase):
    """
    Test class for the verdict class
    """

    # #################### Init and deinit functions #########################
    def setUp(self):
        """
            Initialize the verdict instance
        """
        self.verdict = Verdict()

    # #################### Tests functions #########################

    # ##### __init__
    def test___init__(self):
        self.assertEqual(self.verdict.get_value(), 'none')
        self.assertEqual(self.verdict.get_message(), '')
        self.assertEqual(str(self.verdict), 'none')

    def test___init__with_initial_value(self):
        for verdict in Verdict.values():
            self.verdict = Verdict(verdict)
            self.assertEqual(
                self.verdict.get_value(),
                verdict
            )
            self.assertEqual(self.verdict.get_message(), '')
            self.assertEqual(
                str(self.verdict),
                verdict
            )

    def test___init__with_int_as_initial_value(self):
        verdict_values = Verdict.values()
        for verdict in verdict_values:
            verdict_id = verdict_values.index(verdict)
            with self.assertRaises(InputParameterError):
                self.verdict = Verdict(verdict_id)

    # ##### update
    def test_update(self):
        for verdict in Verdict.values():
            if verdict != 'none':  # Because initial one is none
                self.verdict.update(verdict, verdict)
                self.assertEqual(self.verdict.get_value(), verdict)
                self.assertEqual(self.verdict.get_message(), verdict)
                self.assertEqual(str(self.verdict), verdict)

    def test_update_with_lower_or_equal_values(self):
        verdict_values = Verdict.values()
        for verdict in verdict_values:

            # Initialize with the verdict
            self.verdict = Verdict(verdict)

            # Try to update with lower or equal values
            for ver in verdict_values:
                if verdict_values.index(ver) <= verdict_values.index(verdict):
                    self.verdict.update(ver, ver)
                    self.assertEqual(self.verdict.get_value(), verdict)
                    self.assertEqual(self.verdict.get_message(), '')
                    self.assertEqual(str(self.verdict), verdict)

    def test_update_with_int_value(self):
        verdict_values = Verdict.values()
        for verdict in verdict_values:

            # Initialize with the verdict
            self.verdict = Verdict(verdict)

            # Try to update with lower or equal values
            for ver in verdict_values:
                next_verdict_id = verdict_values.index(ver)
                with self.assertRaises(InputParameterError):
                    self.verdict.update(next_verdict_id, '')

    # ##### values
    def test_values(self):
        verdict_values = Verdict.values()
        self.assertIsInstance(verdict_values, tuple)
        self.assertGreater(len(verdict_values), 0)
        for verdict in verdict_values:
            self.assertIsInstance(verdict, str)

    # ##### get_value
    def test_get_value(self):
        for verdict in Verdict.values():

            # Initialize with the verdict
            self.verdict = Verdict(verdict)

            # Try to get its value
            self.assertEqual(self.verdict.get_value(), verdict)

    # ##### get_message
    def test_get_message(self):
        verdict_values = Verdict.values()
        for verdict in Verdict.values():

            # Initialize with the verdict
            self.verdict = Verdict(verdict)
            next_verdict_id = verdict_values.index(verdict) + 1

            if next_verdict_id < len(verdict_values):
                self.verdict.update(verdict_values[next_verdict_id], verdict)
                self.assertEqual(self.verdict.get_message(), verdict)

    # ##### __str__
    def test___str__(self):
        for verdict in Verdict.values():

            # Initialize with the verdict
            self.verdict = Verdict(verdict)

            # Try to get its value
            self.assertEqual(str(self.verdict), verdict)

# #################### Main run the tests #########################
if __name__ == '__main__':
    unittest.main()
