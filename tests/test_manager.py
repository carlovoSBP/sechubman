import os
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml

from sechubman import Manager

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES_DOCUMENT = yaml.safe_load(file)
with Path("tests/fixtures/rules/condensed_rules.yaml").open() as file:
    CONDENSED_RULES_DOCUMENT = yaml.safe_load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")


class TestFromRulesDocument(TestCase):
    def test_without_manager_config(self):
        manager = Manager.from_rules_document(
            CORRECT_RULES_DOCUMENT, SECURITYHUB_SESSION_CLIENT
        )
        self.assertIsInstance(manager, Manager)
        registered_rules = manager._rules  # noqa: SLF001
        self.assertEqual(len(registered_rules), len(CORRECT_RULES_DOCUMENT["Rules"]))

    def test_with_manager_config(self):
        manager = Manager.from_rules_document(
            CONDENSED_RULES_DOCUMENT, SECURITYHUB_SESSION_CLIENT
        )
        self.assertIsInstance(manager, Manager)
        registered_rules = manager._rules  # noqa: SLF001
        self.assertEqual(len(registered_rules), len(CONDENSED_RULES_DOCUMENT["Rules"]))

    def test_requires_a_rules_key(self):
        with self.assertRaises(ValueError):
            Manager.from_rules_document({}, SECURITYHUB_SESSION_CLIENT)

    def test_rejects_unknown_manager_config_keys(self):
        # The common mistake: putting ExtraFeatures next to, rather than inside,
        # DefaultRuleInput.
        rules = {
            "ManagerConfig": {
                "DefaultRuleInput": {},
                "ExtraFeatures": {"NoteTextConfig": {"Mode": "jsonUpdate", "Key": "x"}},
            },
            "Rules": [],
        }
        with self.assertRaises(ValueError):
            Manager.from_rules_document(rules, SECURITYHUB_SESSION_CLIENT)
