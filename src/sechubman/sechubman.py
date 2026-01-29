"""The main module of sechubman."""

import logging
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

import botocore.session
from botocore.client import BaseClient

from .securityhub import (
    AwsSecurityFindingFilters,
    create_aws_security_findings_filters_from_dicts,
)
from .utils import (
    BotoStubCall,
    get_finding_values_from_boto_argument,
    validate_boto_call_params,
)

LOGGER = logging.getLogger(__name__)


def _validate_securityhub_call_params(
    boto_stub_responses: list[BotoStubCall],
    securityhub_session_client: BaseClient | None = None,
) -> bool:
    if not securityhub_session_client:
        securityhub_session_client = botocore.session.get_session().create_client(
            "securityhub"
        )

    return validate_boto_call_params(boto_stub_responses, securityhub_session_client)


def validate_filters(
    filters: dict, securityhub_session_client: BaseClient | None = None
) -> bool:
    """Validate AWS SecurityHub filters to get findings.

    Parameters
    ----------
    filters : dict
        The filters to validate
    securityhub_session_client : BaseClient, optional
        A boto session BaseClient for AWS SecurityHub
        Tries to create one if not provided

    Returns
    -------
    bool
        True if the filters are valid, False otherwise
    """
    return _validate_securityhub_call_params(
        [
            BotoStubCall(
                method="get_findings",
                service_response={"Findings": []},
                expected_params={"Filters": filters},
            )
        ],
        securityhub_session_client,
    )


def validate_updates(
    updates: dict, securityhub_session_client: BaseClient | None = None
) -> bool:
    """Validate AWS SecurityHub updates to findings.

    Parameters
    ----------
    updates : dict
        The updates to make to (a set of) findings
    securityhub_session_client : BaseClient, optional
        A boto session BaseClient for AWS SecurityHub
        Tries to create one if not provided

    Returns
    -------
    bool
        True if the updates are valid, False otherwise
    """
    return _validate_securityhub_call_params(
        [
            BotoStubCall(
                method="batch_update_findings",
                service_response={"ProcessedFindings": [], "UnprocessedFindings": []},
                expected_params=updates,
            )
        ],
        securityhub_session_client,
    )


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
