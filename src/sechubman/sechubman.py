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
