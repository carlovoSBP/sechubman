"""The domain model that simplifies rule management."""

import logging
from dataclasses import dataclass, field
from typing import Any

from botocore.client import BaseClient

from sechubman.rule import Rule

LOGGER = logging.getLogger(__name__)


@dataclass
class Manager:
    """Dataclass managing rule creation."""

    DefaultRuleInput: dict[str, Any]
    client: BaseClient
    rules: list[Rule] = field(default_factory=list)

    def _merge_inputs(
        self,
        default_input: dict[str, Any],
        rule_input: dict[str, Any],
    ) -> dict[str, Any]:
        """Recursively merge default and rule input dictionaries."""
        merged: dict[str, Any] = default_input.copy()
        for key, value in rule_input.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._merge_inputs(merged[key], value)
            else:
                merged[key] = value
        return merged

    def set_rules(self, rules_input: list[dict[str, Any]]) -> list[Rule]:
        """Create rules based on the provided input and the default rule input.

        Parameters
        ----------
        rules_input : list[dict[str, Any]]
            A list of dictionaries containing the rule input. Each dictionary will be merged with the DefaultRuleInput to create a complete rule input.

        Returns
        -------
        list[Rule]
            A list of Rule instances created from the input.
        """
        self.rules = []
        for rule_input in rules_input:
            merged_input = self._merge_inputs(self.DefaultRuleInput, rule_input)
            self.rules.append(Rule(**merged_input, client=self.client))
        return self.rules

    def get_and_update_all(self) -> bool:
        """Get all the findings matching the rules' filters from AWS SecurityHub and update them according to the rules' updates.

        Returns
        -------
        bool
            True if all findings were processed successfully, False otherwise
        """
        all_success = True
        for index, rule in enumerate(self.rules):
            LOGGER.info("Updating findings for rule no. %d", index + 1)
            success = rule.get_and_update()
            if not success:
                all_success = False
        return all_success
