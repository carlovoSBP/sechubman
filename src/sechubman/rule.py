"""The main domain model of sechubman."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from botocore.client import BaseClient

from .boto_utils import (
    get_values_by_boto_argument,
)
from .filters import Filter, create_filters
from .sechubman import validate_filters, validate_updates

LOGGER = logging.getLogger(__name__)


@dataclass
class Rule:
    """Dataclass representing a SecurityHub management rule."""

    Filters: dict[str, list[dict[str, Any]]]
    UpdatesToFilteredFindings: dict[str, Any]
    client: BaseClient
    ExtraFeatures: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the rule upon initialization."""
        self._validate_boto_compatibility()
        self._filters = self._create_filters()
        self._regex_string_filters = self._create_regex_string_filters()

    def _create_regex_string_filters(self) -> dict[str, list[re.Pattern[str]]]:
        """Validate and compile regex string filters from ExtraFeatures."""
        if not self.ExtraFeatures:
            return {}

        allowed_extra_features = {"RegexStringFilters"}
        unknown_features = set(self.ExtraFeatures).difference(allowed_extra_features)
        if unknown_features:
            msg = f"Unsupported extra feature(s): {sorted(unknown_features)}"
            raise ValueError(msg)

        regex_string_filters = self.ExtraFeatures.get("RegexStringFilters", {})
        if not isinstance(regex_string_filters, dict):
            msg = "'ExtraFeatures.RegexStringFilters' should be a dictionary"
            raise TypeError(msg)

        compiled_filters: dict[str, list[re.Pattern[str]]] = {}
        for field_name, patterns in regex_string_filters.items():
            if not isinstance(field_name, str):
                msg = "'ExtraFeatures.RegexStringFilters' keys should be strings"
                raise TypeError(msg)
            if not isinstance(patterns, list):
                msg = "Each value in 'ExtraFeatures.RegexStringFilters' should be a list of regex strings"
                raise TypeError(msg)

            compiled_patterns: list[re.Pattern[str]] = []
            for pattern in patterns:
                if not isinstance(pattern, str):
                    msg = "Each pattern in 'ExtraFeatures.RegexStringFilters' should be a string"
                    raise TypeError(msg)
                try:
                    compiled_patterns.append(re.compile(pattern))
                except re.error as exc:
                    msg = f"Invalid regex pattern '{pattern}' for '{field_name}': {exc}"
                    raise ValueError(msg) from exc

            compiled_filters[field_name] = compiled_patterns

        return compiled_filters

    def _validate_updates_to_filtered_findings(self) -> None:
        """Validate the UpdatesToFilteredFindings argument.

        Raises
        ------
        botocore.exceptions.ParamValidationError
            If the UpdatesToFilteredFindings argument contains invalid values
        ValueError
            If 'FindingIdentifiers' is directly set in UpdatesToFilteredFindings
        """
        if "FindingIdentifiers" in self.UpdatesToFilteredFindings:
            msg = "'FindingIdentifiers' should not be directly set in 'UpdatesToFilteredFindings'"
            raise ValueError(msg)

        updates_copy = self.UpdatesToFilteredFindings.copy()
        updates_copy["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]

        validate_updates(updates_copy, self.client)

    def _validate_boto_compatibility(self) -> None:
        """Validate the rule beyond the top-level arguments.

        Raises
        ------
        botocore.exceptions.ParamValidationError
            If the rule is invalid beyond the top-level arguments
        """
        validate_filters(self.Filters, self.client)
        self._validate_updates_to_filtered_findings()

    def _create_filters(
        self,
    ) -> dict[str, Filter]:
        """Get the rule's filters as AwsSecurityFindingFilters instances.

        Returns
        -------
        dict[str, AwsSecurityFindingFilters]
            The rule's filters as AwsSecurityFindingFilters instances
        """
        return {
            filter_name: create_filters(filters_dicts)
            for filter_name, filters_dicts in self.Filters.items()
        }

    def get_and_update(self) -> bool:
        """Get all the findings matching the rule's filters from AWS SecurityHub and update them according to the rule's updates.

        Returns
        -------
        bool
            True if all findings were processed successfully, False otherwise
        """
        paginator = self.client.get_paginator("get_findings")
        page_iterator = paginator.paginate(
            Filters=self.Filters, PaginationConfig={"MaxItems": 100, "PageSize": 100}
        )

        updates = self.UpdatesToFilteredFindings.copy()

        any_unprocessed = False

        for page in page_iterator:
            updates["FindingIdentifiers"] = [
                {
                    "Id": finding["Id"],
                    "ProductArn": finding["ProductArn"],
                }
                for finding in page["Findings"]
                if self._match_regex_string_filters(finding)
            ]

            if not updates["FindingIdentifiers"]:
                LOGGER.info(
                    "No (more) findings matched the filters; nothing to update."
                )
                break

            response = self.client.batch_update_findings(**updates)
            processed = response["ProcessedFindings"]
            unprocessed = response["UnprocessedFindings"]

            LOGGER.info("Number of processed findings: %d", len(processed))
            if unprocessed:
                any_unprocessed = True
                LOGGER.warning("Number of unprocessed findings: %d", len(unprocessed))

        return not any_unprocessed

    def _match_regex_string_filters(self, finding: dict[str, Any]) -> bool:
        """Check if a finding matches all configured regex string filters."""
        return all(
            any(
                isinstance(value, str)
                and any(pattern.search(value) for pattern in compiled_patterns)
                for value in get_values_by_boto_argument(finding, filter_name)
            )
            for filter_name, compiled_patterns in self._regex_string_filters.items()
        )

    def match(self, finding: dict) -> bool:
        """Check if a finding matches the rule's filters.

        Parameters
        ----------
        finding : dict
            The finding to check

        Returns
        -------
        bool
            True if the finding matches the rule's filters, False otherwise
        """
        boto_filters_match = all(
            (
                any(
                    aws_security_finding_filters.match(value)
                    for value in get_values_by_boto_argument(finding, filter_name)
                )
            )
            for filter_name, aws_security_finding_filters in self._filters.items()
        )
        return boto_filters_match and self._match_regex_string_filters(finding)
