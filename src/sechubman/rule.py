"""The main domain model of sechubman."""

import logging
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

from botocore.client import BaseClient

from .boto import (
    get_finding_values_from_boto_argument,
)
from .boto.securityhub import (
    AwsSecurityFindingFilters,
    create_aws_security_findings_filters_from_dicts,
)
from .sechubman import validate_filters, validate_updates

LOGGER = logging.getLogger(__name__)


@dataclass
class Rule:
    """Dataclass representing a SecurityHub management rule."""

    Filters: dict[str, list[dict[str, Any]]]
    UpdatesToFilteredFindings: dict[str, Any]
    boto_securityhub_client: BaseClient

    def _validate_updates_to_filtered_findings(self) -> bool:
        """Validate the updates_to_filtered_findings argument.

        Returns
        -------
        bool
            True if the updates_to_filtered_findings argument is valid, False otherwise
        """
        if "FindingIdentifiers" in self.UpdatesToFilteredFindings:
            LOGGER.warning(
                "Validation error: 'FindingIdentifiers' should not be directly set in 'updates_to_filtered_findings'"
            )
            return False

        updates_copy = self.UpdatesToFilteredFindings.copy()
        updates_copy["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]

        return validate_updates(updates_copy, self.boto_securityhub_client)

    def validate_deep(self) -> bool:
        """Validate the rule beyond the top-level arguments.

        Returns
        -------
        bool
            True if the rule is valid beyond the top-level arguments, False otherwise
        """
        filters_valid = validate_filters(self.Filters, self.boto_securityhub_client)
        updates_valid = self._validate_updates_to_filtered_findings()

        return filters_valid and updates_valid

    def apply(self) -> bool:
        """Apply the rule in AWS SecurityHub.

        Returns
        -------
        bool
            True if all findings were processed successfully, False otherwise
        """
        paginator = self.boto_securityhub_client.get_paginator("get_findings")
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
            ]

            if not updates["FindingIdentifiers"]:
                LOGGER.info(
                    "No (more) findings matched the filters; nothing to update."
                )
                break

            response = self.boto_securityhub_client.batch_update_findings(**updates)
            processed = response["ProcessedFindings"]
            unprocessed = response["UnprocessedFindings"]

            LOGGER.info("Number of processed findings: %d", len(processed))
            if unprocessed:
                any_unprocessed = True
                LOGGER.warning("Number of unprocessed findings: %d", len(unprocessed))

        return not any_unprocessed

    def _get_filters(
        self,
    ) -> Generator[tuple[str, AwsSecurityFindingFilters], None, None]:
        """Get the rule's filters as AwsSecurityFindingFilters instances.

        Returns
        -------
        Generator[tuple[str, AwsSecurityFindingFilters], None, None]
            The rule's filters as AwsSecurityFindingFilters instances
        """
        return (
            (
                filter_name,
                create_aws_security_findings_filters_from_dicts(filters_dicts),
            )
            for filter_name, filters_dicts in self.Filters.items()
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
        return all(
            (
                any(
                    aws_security_finding_filters.match(value)
                    for value in get_finding_values_from_boto_argument(
                        finding, filter_name
                    )
                )
            )
            for filter_name, aws_security_finding_filters in self._get_filters()
        )
