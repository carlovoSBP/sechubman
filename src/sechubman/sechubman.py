"""The main module of sechubman."""

import botocore.session
from botocore.client import BaseClient

from .boto import (
    BotoStubCall,
    validate_boto_call_params,
)


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
