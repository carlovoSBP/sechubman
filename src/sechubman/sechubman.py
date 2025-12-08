"""The main module of sechubman."""

import logging

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
