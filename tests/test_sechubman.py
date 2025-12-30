import json
import os
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml
from botocore.stub import Stubber

from sechubman import Rule, validate_filters, validate_updates

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
# Not strictly needed, but speeds up boto3 client creation
os.environ["AWS_ACCESS_KEY_ID"] = "ASIA000AAA"
os.environ["AWS_SECRET_ACCESS_KEY"] = "abc123"  # noqa: S105
os.environ["AWS_SESSION_TOKEN"] = "abc123token"  # noqa: S105


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

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")


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
        rule = Rule(
            **CORRECT_RULES[0], boto3_security_hub_client=SECURITYHUB_SESSION_CLIENT
        )
        self.assertTrue(rule.validate_deep())

    def test_invalid_rule_boto3(self):
        rule = Rule(
            **BROKEN_RULES[0], boto3_security_hub_client=SECURITYHUB_SESSION_CLIENT
        )
        self.assertFalse(rule.validate_deep())

    def test_invalid_rule_business_logic(self):
        rule = Rule(
            **BROKEN_RULES[1], boto3_security_hub_client=SECURITYHUB_SESSION_CLIENT
        )
        self.assertFalse(rule.validate_deep())

    def test_apply(self):
        stubber = Stubber(SECURITYHUB_SESSION_CLIENT)

        stubber.add_response("get_findings", FINDINGS, FILTERS)
        stubber.add_response("batch_update_findings", PROCESSED, UPDATES)

        stubber.activate()

        rule = Rule(
            **CORRECT_RULES[0], boto3_security_hub_client=SECURITYHUB_SESSION_CLIENT
        )
        rule.apply()

        stubber.deactivate()
