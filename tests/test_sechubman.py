import os
from pathlib import Path
from unittest import TestCase

import yaml

from sechubman import Rule, validate_filters, validate_updates

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"


with Path("tests/fixtures/correct_rules.yaml").open() as file:
    CORRECT_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/broken_rules.yaml").open() as file:
    BROKEN_RULES = yaml.safe_load(file)["Rules"]


class TestSmoke(TestCase):
    def test_sanity(self):
        self.assertTrue(expr=True)


class TestValidateFilters(TestCase):
    def test_valid_filters(self):
        self.assertTrue(validate_filters(CORRECT_RULES[0]["Filters"]))

    def test_invalid_filters(self):
        self.assertFalse(validate_filters(BROKEN_RULES[0]["Filters"]))


class TestValidateUpdates(TestCase):
    def test_valid_updates(self):
        first_rule_updates = CORRECT_RULES[0]["UpdatesToFilteredFindings"]
        first_rule_updates["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]
        self.assertTrue(validate_updates(first_rule_updates))

    def test_invalid_updates(self):
        self.assertFalse(validate_updates(BROKEN_RULES[0]["UpdatesToFilteredFindings"]))


class TestRuleDataclass(TestCase):
    def test_valid_rule(self):
        rule = Rule(**CORRECT_RULES[0], is_deep_validated=False)
        rule.validate_deep()
        self.assertTrue(rule.is_deep_validated)

    def test_invalid_rule_boto3(self):
        rule = Rule(**BROKEN_RULES[0])
        self.assertFalse(rule.is_deep_validated)

    def test_invalid_rule_business_logic(self):
        rule = Rule(**BROKEN_RULES[1])
        self.assertFalse(rule.is_deep_validated)
