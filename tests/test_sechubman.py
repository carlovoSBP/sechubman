from unittest import TestCase

from sechubman import hello


class TestSmoke(TestCase):
    def test_sanity(self):
        self.assertTrue(True)

    def test_integration(self):
        self.assertEqual("Hello you from sechubman!", hello())
