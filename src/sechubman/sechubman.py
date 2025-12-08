"""The main module of sechubman."""

import logging
from dataclasses import dataclass

import botocore.session
from botocore.exceptions import ParamValidationError
from botocore.stub import Stubber

LOGGER = logging.getLogger(__name__)


def validate_filters(filters: dict) -> bool:
    """Validate AWS Security Hub filters to get findings.

    Parameters
    ----------
    filters : dict
        The filters to validate

    Returns
    -------
    bool
        True if the filters are valid, False otherwise
    """
    securityhub = botocore.session.get_session().create_client("securityhub")
    stubber = Stubber(securityhub)

    stubber.add_response("get_findings", {"Findings": []}, {"Filters": filters})
    stubber.activate()

    valid = False

    try:
        securityhub.get_findings(Filters=filters)
    except ParamValidationError as e:
        LOGGER.warning("Validation error: %s", e)
    else:
        valid = True
    finally:
        stubber.deactivate()

    return valid


def validate_updates(updates: dict) -> bool:
    """Validate AWS Security Hub updates to findings.

    Parameters
    ----------
    updates : dict
        The updates to make to a (set of) findings

    Returns
    -------
    bool
        True if the updates are valid, False otherwise
    """
    securityhub = botocore.session.get_session().create_client("securityhub")
    stubber = Stubber(securityhub)

    stubber.add_response(
        "batch_update_findings",
        {"ProcessedFindings": [], "UnprocessedFindings": []},
        updates,
    )
    stubber.activate()

    valid = False

    try:
        securityhub.batch_update_findings(**updates)
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
                "Validation error: 'FindingIdentifiers' should not be directly set in UpdatesToFilteredFindings"
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
        Set is_deep_validated to whether the deep rule is valid.

        Returns
        -------
        bool
            True if the rule is valid beyond the top-level arguments, False otherwise
        """
        filters_valid = validate_filters(self.Filters)
        updates_valid = self._validate_updates_to_filtered_findings()

        self.is_deep_validated = filters_valid and updates_valid

        return self.is_deep_validated
