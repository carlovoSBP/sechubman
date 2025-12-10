import json
import os
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml
from botocore.stub import Stubber

from sechubman import Rule, validate_filters, validate_updates

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/broken_rules.yaml").open() as file:
    BROKEN_RULES = yaml.safe_load(file)["Rules"]

with Path("tests/fixtures/boto3/filters.json").open() as file:
    FILTERS = json.load(file)
with Path("tests/fixtures/boto3/findings_trimmed.json").open() as file:
    FINDINGS = json.load(file)
with Path("tests/fixtures/boto3/updates.json").open() as file:
    UPDATES = json.load(file)
with Path("tests/fixtures/boto3/processed.json").open() as file:
    PROCESSED = json.load(file)


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

    def test_apply(self):
        securityhub_session_client = botocore.session.get_session().create_client(
            "securityhub"
        )
        stubber = Stubber(securityhub_session_client)

        stubber.add_response("get_findings", FINDINGS, FILTERS)
        stubber.add_response("batch_update_findings", PROCESSED, UPDATES)

        stubber.activate()

        rule = Rule(**CORRECT_RULES[0], is_deep_validated=False)
        rule.apply(securityhub_session_client)

        stubber.deactivate()
