import unittest
from ttproto.utils.version_git import get_git_version


class VersionTestCase(unittest.TestCase):

    def test_not_none(self):
        self.assertIsNotNone(get_git_version(), "git version shouldnt be none")

if __name__ == '__main__':
    unittest.main()
