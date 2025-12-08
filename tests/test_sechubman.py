from pathlib import Path
from unittest import TestCase

import yaml

from sechubman import validate_filters


class TestSmoke(TestCase):
    def test_sanity(self):
        self.assertTrue(expr=True)


class TestValidateFilters(TestCase):
    def test_valid_filters(self):
        with Path("tests/fixtures/correct_rules.yaml").open() as file:
            rules = yaml.safe_load(file)
        self.assertTrue(validate_filters(rules["Rules"][0]["Filters"]))

    def test_invalid_filters(self):
        with Path("tests/fixtures/broken_rules.yaml").open() as file:
            rules = yaml.safe_load(file)
        self.assertFalse(validate_filters(rules["Rules"][0]["Filters"]))
