import os
from pathlib import Path
from unittest import TestCase

import yaml

from sechubman import validate_filters, validate_updates

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"


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


class TestValidateUpdates(TestCase):
    def test_valid_updates(self):
        with Path("tests/fixtures/correct_rules.yaml").open() as file:
            rules = yaml.safe_load(file)
        first_rule_updates = rules["Rules"][0]["UpdatesToFilteredFindings"]
        first_rule_updates["FindingIdentifiers"] = [
            {
                "Id": "arn:aws:securityhub:eu-west-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.1/finding/abcd1234-5678-90ab-cdef-EXAMPLE11111",
                "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
            }
        ]
        self.assertTrue(validate_updates(first_rule_updates))

    def test_invalid_updates(self):
        with Path("tests/fixtures/broken_rules.yaml").open() as file:
            rules = yaml.safe_load(file)
        self.assertFalse(
            validate_updates(rules["Rules"][0]["UpdatesToFilteredFindings"])
        )
