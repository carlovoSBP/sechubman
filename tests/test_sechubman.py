import datetime
import json
import os
from copy import deepcopy
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import botocore.session
import yaml
from botocore.exceptions import ParamValidationError

from sechubman import (
    Manager,
    Rule,
    validate_filters,
    validate_updates,
)
from sechubman.boto_utils import (
    BotoStubCall,
    get_values_by_boto_argument,
    stub_boto_client,
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
with Path("tests/fixtures/rules/condensed_rules.yaml").open() as file:
    CONDENSED_RULES = yaml.safe_load(file)
with Path("tests/fixtures/rules/all_filter_types_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_MATCH_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/all_filter_types_no_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_NO_MATCH_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/json_update_rules.yaml").open() as file:
    JSON_RULES = yaml.safe_load(file)["Rules"]

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
with Path("tests/fixtures/calls/json_updates.json").open() as file:
    JSON_UPDATES = json.load(file)

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


class TestGetValuesByBotoArgument(TestCase):
    def test_regular_field_returns_single_value(self):
        finding = {"Title": "Some title"}
        self.assertEqual(get_values_by_boto_argument(finding, "Title"), ["Some title"])

    def test_regular_missing_field_returns_empty_list(self):
        finding = {"Title": "Some title"}
        self.assertEqual(get_values_by_boto_argument(finding, "Description"), [])

    def test_special_case_nested_list_path(self):
        finding = {
            "Resources": [
                {"Id": "res-1", "Type": "AwsS3Bucket"},
                {"Id": "res-2", "Type": "AwsEc2Instance"},
            ]
        }
        self.assertEqual(
            get_values_by_boto_argument(finding, "ResourceId"),
            ["res-1", "res-2"],
        )

    def test_special_case_ignores_missing_and_none_values(self):
        finding = {
            "Resources": [
                {"Id": "res-1"},
                {"Id": None},
                {},
            ]
        }
        self.assertEqual(get_values_by_boto_argument(finding, "ResourceId"), ["res-1"])

    def test_empty_tags(self):
        finding = {"Tags": {}}
        self.assertEqual(get_values_by_boto_argument(finding, "Tags"), [])

    def test_empty_resource_tags(self):
        finding = {
            "Resources": [
                {"Tags": {}},
            ]
        }
        self.assertEqual(get_values_by_boto_argument(finding, "ResourceTags"), [])

    def test_empty_types(self):
        finding = {"Types": []}
        self.assertEqual(get_values_by_boto_argument(finding, "Type"), [])


class TestRuleDataclass(TestCase):
    def setUp(self):
        self.fixed_now = datetime.datetime(2026, 1, 1, 12, 0, 0, 0, datetime.UTC)
        patcher = patch(
            "sechubman.filters.DateCriterion._now_utc",
            return_value=self.fixed_now,
        )
        self.addCleanup(patcher.stop)
        self.mock_now = patcher.start()

    def _test_multiple_valid_rules(self, rules: list[dict]):
        for rule_dict in rules:
            with self.subTest(rule=rule_dict):
                Rule(**rule_dict, client=SECURITYHUB_SESSION_CLIENT)

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
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_invalid_rule_business_logic(self):
        self.assertRaises(
            ValueError,
            Rule,
            **BROKEN_RULES[1],
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_invalid_regex_rule_boto(self):
        self.assertRaises(
            ParamValidationError,
            Rule,
            **BROKEN_RULES[2],
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_apply(self):
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_manager_apply(self):
        manager = Manager(
            **CONDENSED_RULES["ManagerConfig"], client=SECURITYHUB_SESSION_CLIENT
        )
        manager.set_rules(CONDENSED_RULES["Rules"])
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            self.assertTrue(manager.get_and_update_all())

    def test_apply_unprocessed(self):
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", UNPROCESSED, UPDATES),
            ],
        ):
            self.assertFalse(rule.get_and_update())

    def test_json_apply(self):
        rule = Rule(**JSON_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", {"Findings": [FINDING_GROOMED]}, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_json_apply_groups_updates_by_resulting_note_text(self):
        rule = Rule(**JSON_RULES[0], client=SECURITYHUB_SESSION_CLIENT)

        finding_one = deepcopy(FINDING_GROOMED)
        finding_one["Id"] = FINDINGS["Findings"][0]["Id"]
        finding_one["Note"]["Text"] = (
            '{"jiraIssue":"PROJ-123","suppressionReason":"override me"}'
        )

        finding_two = deepcopy(FINDING_GROOMED)
        finding_two["Id"] = FINDINGS["Findings"][1]["Id"]
        finding_two["Note"]["Text"] = (
            '{"jiraIssue":"PROJ-123","suppressionReason":"some old value"}'
        )

        finding_three = deepcopy(FINDING_GROOMED)
        finding_three["Id"] = FINDINGS["Findings"][2]["Id"]
        finding_three["Note"]["Text"] = (
            '{"jiraIssue":"PROJ-456","suppressionReason":"override me"}'
        )

        updates_for_proj_123 = {
            "Note": {
                "Text": '{"jiraIssue":"PROJ-123","suppressionReason":"Test test"}',
                "UpdatedBy": "sechubman",
            },
            "FindingIdentifiers": [
                {
                    "Id": finding_one["Id"],
                    "ProductArn": finding_one["ProductArn"],
                },
                {
                    "Id": finding_two["Id"],
                    "ProductArn": finding_two["ProductArn"],
                },
            ],
        }
        updates_for_proj_456 = {
            "Note": {
                "Text": '{"jiraIssue":"PROJ-456","suppressionReason":"Test test"}',
                "UpdatedBy": "sechubman",
            },
            "FindingIdentifiers": [
                {
                    "Id": finding_three["Id"],
                    "ProductArn": finding_three["ProductArn"],
                }
            ],
        }

        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall(
                    "get_findings",
                    {"Findings": [finding_one, finding_two, finding_three]},
                    FILTERS,
                ),
                BotoStubCall("batch_update_findings", PROCESSED, updates_for_proj_123),
                BotoStubCall("batch_update_findings", PROCESSED, updates_for_proj_456),
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_manager_json_apply(self):
        manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
        manager.set_rules(JSON_RULES)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
            ],
        ):
            self.assertTrue(manager.match_and_update(FINDING_GROOMED))

    def test_match(self):
        for all_filter_type_match_rule in ALL_FILTER_TYPES_MATCH_RULES:
            with self.subTest(all_filter_type_match_rule=all_filter_type_match_rule):
                rule = Rule(
                    **all_filter_type_match_rule,
                    client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertTrue(rule.match(FINDING_GROOMED))

    def test_no_match(self):
        for all_filter_type_no_match_rule in ALL_FILTER_TYPES_NO_MATCH_RULES:
            with self.subTest(
                all_filter_type_no_match_rule=all_filter_type_no_match_rule
            ):
                rule = Rule(
                    **all_filter_type_no_match_rule,
                    client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertFalse(rule.match(FINDING_GROOMED))
