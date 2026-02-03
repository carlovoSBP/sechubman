import datetime
import json
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import botocore.session
import yaml
from botocore.exceptions import ParamValidationError

from sechubman import (
    Rule,
    validate_filters,
    validate_updates,
)
from sechubman.boto_utils import BotoStubCall, stub_boto_client

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

with Path("tests/fixtures/calls/filters.json").open() as file:
    FILTERS = json.load(file)
with Path("tests/fixtures/responses/findings_trimmed.json").open() as file:
    FINDINGS = json.load(file)
with Path("tests/fixtures/responses/finding_groomed.json").open() as file:
    FINDING_GROOMED = json.load(file)
with Path("tests/fixtures/calls/updates.json").open() as file:
    UPDATES = json.load(file)
with Path("tests/fixtures/responses/processed.json").open() as file:
    PROCESSED = json.load(file)
with Path("tests/fixtures/responses/unprocessed.json").open() as file:
    UNPROCESSED = json.load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")


class TestSmoke(TestCase):
    def test_sanity(self):
        self.assertTrue(expr=True)


class TestValidateFilters(TestCase):
    def test_valid_filters(self):
        self.assertIsNone(validate_filters(CORRECT_RULES[0]["Filters"]))

    def test_invalid_filters(self):
        self.assertRaises(
            ParamValidationError, validate_filters, BROKEN_RULES[0]["Filters"]
        )


class TestValidateUpdates(TestCase):
    def test_valid_updates(self):
        first_rule_updates = CORRECT_RULES[0]["UpdatesToFilteredFindings"]
        first_rule_updates["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]
        self.assertIsNone(validate_updates(first_rule_updates))

    def test_invalid_updates(self):
        self.assertRaises(
            ParamValidationError,
            validate_updates,
            BROKEN_RULES[0]["UpdatesToFilteredFindings"],
        )


class TestRuleDataclass(TestCase):
    def setUp(self):
        self.fixed_now = datetime.datetime(2026, 1, 1, 12, 0, 0, 0, datetime.UTC)
        patcher = patch(
            "sechubman.filters.DateFilter._now_utc",
            return_value=self.fixed_now,
        )
        self.addCleanup(patcher.stop)
        self.mock_now = patcher.start()

    def _test_multiple_valid_rules(self, rules: list[dict]):
        for rule_dict in rules:
            with self.subTest(rule=rule_dict):
                Rule(**rule_dict, boto_securityhub_client=SECURITYHUB_SESSION_CLIENT)

    def test_valid_rule(self):
        self._test_multiple_valid_rules(CORRECT_RULES)

    def test_all_type_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_MATCH_RULES)

    def test_all_type_no_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_NO_MATCH_RULES)

    def test_invalid_rule_boto(self):
        self.assertRaises(
            ParamValidationError,
            Rule,
            **BROKEN_RULES[0],
            boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_invalid_rule_business_logic(self):
        self.assertRaises(
            ValueError,
            Rule,
            **BROKEN_RULES[1],
            boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_apply(self):
        rule = Rule(
            **CORRECT_RULES[0], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
        )
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            self.assertTrue(rule.apply())

    def test_apply_unprocessed(self):
        rule = Rule(
            **CORRECT_RULES[0], boto_securityhub_client=SECURITYHUB_SESSION_CLIENT
        )
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", UNPROCESSED, UPDATES),
            ],
        ):
            self.assertFalse(rule.apply())

    def test_match(self):
        for all_filter_type_match_rule in ALL_FILTER_TYPES_MATCH_RULES:
            with self.subTest(all_filter_type_match_rule=all_filter_type_match_rule):
                rule = Rule(
                    **all_filter_type_match_rule,
                    boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertTrue(rule.match(FINDING_GROOMED))

    def test_no_match(self):
        for all_filter_type_no_match_rule in ALL_FILTER_TYPES_NO_MATCH_RULES:
            with self.subTest(
                all_filter_type_no_match_rule=all_filter_type_no_match_rule
            ):
                rule = Rule(
                    **all_filter_type_no_match_rule,
                    boto_securityhub_client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertFalse(rule.match(FINDING_GROOMED))
