"""The main domain model of sechubman."""

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from botocore.client import BaseClient

from .boto_utils import (
    get_values_by_boto_argument,
)
from .filters import (
    Filter,
    RegexStringFilter,
    create_filters,
    create_regex_string_filters,
)
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
        self._note_text_config = self._create_note_text_config()

    def _create_regex_string_filters(self) -> dict[str, RegexStringFilter]:
        """Create regex string filters from ExtraFeatures."""
        if not self.ExtraFeatures:
            return {}

        allowed_extra_features = {"RegexStringFilters", "NoteTextConfig"}
        unknown_features = set(self.ExtraFeatures).difference(allowed_extra_features)
        if unknown_features:
            msg = f"Unsupported extra feature(s): {sorted(unknown_features)}"
            raise ValueError(msg)

        regex_string_filters = self.ExtraFeatures.get("RegexStringFilters", {})
        return create_regex_string_filters(regex_string_filters, self.client)

    def _create_note_text_config(self) -> dict[str, str]:
        """Create note text configuration from ExtraFeatures."""
        if not self.ExtraFeatures or "NoteTextConfig" not in self.ExtraFeatures:
            return {}

        note_text_config = self.ExtraFeatures["NoteTextConfig"]
        if not isinstance(note_text_config, dict):
            msg = "'ExtraFeatures.NoteTextConfig' should be a dictionary"
            raise TypeError(msg)

        mode = note_text_config.get("Mode", "plaintext")
        if mode not in {"plaintext", "jsonUpdate"}:
            msg = (
                "'ExtraFeatures.NoteTextConfig.Mode' should be one of "
                "'plaintext' or 'jsonUpdate'"
            )
            raise ValueError(msg)

        config: dict[str, str] = {"Mode": mode}
        if mode == "jsonUpdate":
            key = note_text_config.get("Key")
            if not isinstance(key, str) or not key:
                msg = (
                    "'ExtraFeatures.NoteTextConfig.Key' should be a non-empty string "
                    "when mode is 'jsonUpdate'"
                )
                raise ValueError(msg)

            config["Key"] = key

        return config

    def _is_json_note_update_mode(self) -> bool:
        """Check whether note text updates should merge existing JSON note metadata."""
        return self._note_text_config.get("Mode") == "jsonUpdate"

    def _parse_note_text_json(self, note_text: str) -> dict[str, Any]:
        """Get existing note metadata from a finding if it is valid JSON object text."""
        try:
            parsed_note = json.loads(note_text)
        except json.JSONDecodeError:
            LOGGER.warning(
                "Existing note text is not JSON and will be overwritten. Previous text: %s",
                note_text,
            )
            return {}

        if not isinstance(parsed_note, dict):
            LOGGER.warning(
                "Existing note JSON is not an object and will be overwritten. Previous text: %s",
                note_text,
            )
            return {}

        return parsed_note

    def _create_note_dict(
        self, finding_note_text: str, note_text_update: str
    ) -> dict[str, Any]:
        """Create the note dictionary for JSON note update mode by merging existing note metadata with the new note updates."""
        note_dict = (
            self._parse_note_text_json(finding_note_text) if finding_note_text else {}
        )
        key = self._note_text_config["Key"]
        note_dict[key] = note_text_update
        return note_dict

    def create_updates_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Create updates payload for a single finding based on this rule's template, including optional JSON note merging.

        Parameters
        ----------
        finding : dict[str, Any]
            The finding for which to create updates.

        Returns
        -------
        dict[str, Any]
            The updates payload for the finding.
        """
        updates = self.UpdatesToFilteredFindings.copy()
        updates["FindingIdentifiers"] = [
            {
                "Id": finding["Id"],
                "ProductArn": finding["ProductArn"],
            }
        ]

        if self._is_json_note_update_mode():
            finding_note = finding.get("Note", {})
            finding_note_text = finding_note.get("Text", "")
            # this saves a deepcopy of self.UpdatesToFilteredFindings
            # which would otherwise be necessary to avoid mutating the rule's template when merging with existing note metadata
            note_updates = updates["Note"].copy()
            note_dict = self._create_note_dict(finding_note_text, note_updates["Text"])
            note_updates["Text"] = json.dumps(note_dict, separators=(",", ":"))
            updates["Note"] = note_updates

        return updates

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
    ) -> dict[str, Filter[Any, Any]]:
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

        any_unprocessed = False
        if not self._is_json_note_update_mode():
            updates = self.UpdatesToFilteredFindings.copy()

        for page in page_iterator:
            matched_findings = [
                finding
                for finding in page["Findings"]
                if self._match(finding, self._regex_string_filters)
            ]

            if not matched_findings:
                LOGGER.info(
                    "No (more) findings matched the filters (in this page); nothing to update."
                )
                continue

            # updates_to_apply must be a list because in jsonUpdate mode,
            # we need to apply different updates for each finding to merge the note text correctly,
            # while in non-jsonUpdate mode we can apply the same updates for all findings
            if self._is_json_note_update_mode():
                updates_to_apply = [
                    self.create_updates_for_finding(finding)
                    for finding in matched_findings
                ]
            else:
                updates["FindingIdentifiers"] = [
                    {
                        "Id": finding["Id"],
                        "ProductArn": finding["ProductArn"],
                    }
                    for finding in matched_findings
                ]
                updates_to_apply = [updates]

            for updates in updates_to_apply:
                response = self.client.batch_update_findings(**updates)
                processed = response["ProcessedFindings"]
                unprocessed = response["UnprocessedFindings"]

                LOGGER.info("Number of processed findings: %d", len(processed))
                if unprocessed:
                    any_unprocessed = True
                    LOGGER.warning(
                        "Number of unprocessed findings: %d", len(unprocessed)
                    )

        return not any_unprocessed

    @staticmethod
    def _match(
        finding: dict[str, Any], filters: Mapping[str, Filter[Any, Any]]
    ) -> bool:
        """Check if a finding matches the filters."""
        return all(
            (
                any(
                    aws_security_finding_filters.match(value)
                    for value in get_values_by_boto_argument(finding, filter_name)
                )
            )
            for filter_name, aws_security_finding_filters in filters.items()
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
        return self._match(finding, self._filters) and self._match(
            finding, self._regex_string_filters
        )
