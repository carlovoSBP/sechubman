import json
import os
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml

from sechubman import (
    BotoStubCall,
    Rule,
    stub_boto_client,
    validate_filters,
    validate_updates,
)

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
# Not strictly needed, but speeds up boto client creation
os.environ["AWS_ACCESS_KEY_ID"] = "ASIA000AAA"
os.environ["AWS_SECRET_ACCESS_KEY"] = "abc123"  # noqa: S105
os.environ["AWS_SESSION_TOKEN"] = "abc123token"  # noqa: S105


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/broken_rules.yaml").open() as file:
    BROKEN_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/all_filter_types_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_MATCH_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/all_filter_types_no_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_NO_MATCH_RULES = yaml.safe_load(file)["Rules"]

with Path("tests/fixtures/boto/filters.json").open() as file:
    FILTERS = json.load(file)
with Path("tests/fixtures/boto/findings_trimmed.json").open() as file:
    FINDINGS = json.load(file)
with Path("tests/fixtures/boto/updates.json").open() as file:
    UPDATES = json.load(file)
with Path("tests/fixtures/boto/processed.json").open() as file:
    PROCESSED = json.load(file)
with Path("tests/fixtures/boto/unprocessed.json").open() as file:
    UNPROCESSED = json.load(file)

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
    def _test_multiple_valid_rules(self, rules: list[dict]):
        for rule_dict in rules:
            with self.subTest(rule=rule_dict):
                rule = Rule(
                    **rule_dict, boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
                )
                self.assertTrue(rule.validate_deep())

    def test_valid_rule(self):
        self._test_multiple_valid_rules(CORRECT_RULES)

    def test_all_type_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_MATCH_RULES)

    def test_all_type_no_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_NO_MATCH_RULES)

    def test_invalid_rule_boto(self):
        rule = Rule(
            **BROKEN_RULES[0], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
        )
        self.assertFalse(rule.validate_deep())

    def test_invalid_rule_business_logic(self):
        rule = Rule(
            **BROKEN_RULES[1], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
        )
        self.assertFalse(rule.validate_deep())

    def test_apply(self):
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            rule = Rule(
                **CORRECT_RULES[0], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
            )
            self.assertTrue(rule.apply())

    def test_apply_unprocessed(self):
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", UNPROCESSED, UPDATES),
            ],
        ):
            rule = Rule(
                **CORRECT_RULES[0], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
            )
            self.assertFalse(rule.apply())

    def test_match(self):
        rule = Rule(
            **ALL_FILTER_TYPES_MATCH_RULES[0],
            boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
        )
        self.assertTrue(rule.match(FINDINGS["Findings"][0]))

    def test_no_match(self):
        for all_filter_type_no_match_rule in ALL_FILTER_TYPES_NO_MATCH_RULES:
            with self.subTest(
                all_filter_type_no_match_rule=all_filter_type_no_match_rule
            ):
                rule = Rule(
                    **all_filter_type_no_match_rule,
                    boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertFalse(rule.match(FINDINGS["Findings"][0]))
