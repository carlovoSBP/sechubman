"""Load every YAML rules example in docs/index.md through Rule/Manager so they cannot silently
break (e.g. the "ExtraFeatures next to DefaultRuleInput" and "NoteTextConfig Key survives a
plaintext override" bugs, both found while validating a real deployment against this library).
"""

import os
import re
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml

from sechubman import Manager, Rule

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")

YAML_FENCE_RE = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _extract_yaml_blocks(markdown_path: str) -> list[dict]:
    text = Path(markdown_path).read_text()
    return [yaml.safe_load(match) for match in YAML_FENCE_RE.findall(text)]


class TestDocsRuleExamples(TestCase):
    def test_every_rules_yaml_example_in_the_docs_is_valid(self):
        blocks = _extract_yaml_blocks("docs/index.md")
        self.assertTrue(blocks, "Expected at least one ```yaml block in docs/index.md")

        for block in blocks:
            with self.subTest(block=block):
                if "ManagerConfig" in block:
                    manager = Manager(
                        **block["ManagerConfig"], client=SECURITYHUB_SESSION_CLIENT
                    )
                    manager.set_rules(block["Rules"])
                else:
                    for rule_input in block["Rules"]:
                        Rule(**rule_input, client=SECURITYHUB_SESSION_CLIENT)
