"""The main module of sechubman."""

import logging
from dataclasses import dataclass

import boto3
import botocore.session
from botocore.client import BaseClient
from botocore.exceptions import ParamValidationError
from botocore.stub import Stubber

LOGGER = logging.getLogger(__name__)


def validate_filters(
    filters: dict, securityhub_session_client: BaseClient | None = None
) -> bool:
    """Validate AWS Security Hub filters to get findings.

    Parameters
    ----------
    filters : dict
        The filters to validate
    securityhub_session_client : BaseClient, optional
        A boto session BaseClient for AWS Security Hub
        Tries to create one if not provided

    Returns
    -------
    bool
        True if the filters are valid, False otherwise
    """
    if not securityhub_session_client:
        securityhub_session_client = botocore.session.get_session().create_client(
            "securityhub"
        )
    stubber = Stubber(securityhub_session_client)

    stubber.add_response("get_findings", {"Findings": []}, {"Filters": filters})
    stubber.activate()

    valid = False

    try:
        securityhub_session_client.get_findings(Filters=filters)
    except ParamValidationError as e:
        LOGGER.warning("Validation error: %s", e)
    else:
        valid = True
    finally:
        stubber.deactivate()

    return valid


def validate_updates(
    updates: dict, securityhub_session_client: BaseClient | None = None
) -> bool:
    """Validate AWS Security Hub updates to findings.

    Parameters
    ----------
    updates : dict
        The updates to make to a (set of) findings
    securityhub_session_client : BaseClient, optional
        A boto session BaseClient for AWS Security Hub
        Tries to create one if not provided

    Returns
    -------
    bool
        True if the updates are valid, False otherwise
    """
    if not securityhub_session_client:
        securityhub_session_client = botocore.session.get_session().create_client(
            "securityhub"
        )
    stubber = Stubber(securityhub_session_client)

    stubber.add_response(
        "batch_update_findings",
        {"ProcessedFindings": [], "UnprocessedFindings": []},
        updates,
    )
    stubber.activate()

    valid = False

    try:
        securityhub_session_client.batch_update_findings(**updates)
    except ParamValidationError as e:
        LOGGER.warning("Validation error: %s", e)
    else:
        valid = True
    finally:
        stubber.deactivate()

    return valid


@dataclass
class Rule:
    """Dataclass representing a Security Hub management rule."""

    Filters: dict
    UpdatesToFilteredFindings: dict
    is_deep_validated: bool = True

    def __post_init__(self) -> None:
        """Perform deep validation after initialization if required."""
        if self.is_deep_validated:
            self.validate_deep()

    def _validate_updates_to_filtered_findings(self) -> bool:
        """Validate the UpdatesToFilteredFindings argument.

        Returns
        -------
        bool
            True if the UpdatesToFilteredFindings argument is valid, False otherwise
        """
        if "FindingIdentifiers" in self.UpdatesToFilteredFindings:
            LOGGER.warning(
                "Validation error: 'FindingIdentifiers' should not be directly set in 'UpdatesToFilteredFindings'"
            )
            return False

        updates_copy = self.UpdatesToFilteredFindings.copy()
        updates_copy["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]

        return validate_updates(updates_copy)

    def validate_deep(self) -> bool:
        """Validate the rule beyond the top-level arguments.

        Also set is_deep_validated to whether the deep rule is valid.

        Returns
        -------
        bool
            True if the rule is valid beyond the top-level arguments, False otherwise
        """
        filters_valid = validate_filters(self.Filters)
        updates_valid = self._validate_updates_to_filtered_findings()

        self.is_deep_validated = filters_valid and updates_valid

        return self.is_deep_validated

    def apply(self, securityhub_client: BaseClient | None = None) -> None:
        """Apply the rule in AWS Security Hub.

        Parameters
        ----------
        securityhub_client : BaseClient, optional
            A boto BaseClient for AWS Security Hub
            Tries to create one if not provided
        """
        if not securityhub_client:
            securityhub_client = boto3.client("securityhub")

        paginator = securityhub_client.get_paginator("get_findings")
        page_iterator = paginator.paginate(
            Filters=self.Filters, PaginationConfig={"MaxItems": 100, "PageSize": 100}
        )

        updates = self.UpdatesToFilteredFindings.copy()

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

            response = securityhub_client.batch_update_findings(**updates)
            processed = response["ProcessedFindings"]
            unprocessed = response["UnprocessedFindings"]

            LOGGER.info("Number of processed findings: %d", len(processed))
            if unprocessed:
                LOGGER.warning("Number of unprocessed findings: %d", len(unprocessed))
