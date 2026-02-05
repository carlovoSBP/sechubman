"""Boto-related utilities for sechubman."""

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from botocore.client import BaseClient
from botocore.stub import Stubber


def get_values_by_boto_argument(finding: dict, name: str) -> list[str]:
    """Get the values in a finding for a given boto argument name.

    Some arguments in:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/client/get_findings.html
    do not directly map to finding fields as per:
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
    Therefore, this method handles those special cases.
    The method returns a list of strings to handle both single-value and multi-value fields.

    Parameters
    ----------
    finding : dict
        The finding to get the values from
    name : str
        The name to get the values for

    Returns
    -------
    list[str]
        The values from the finding for the given name
    """
    if name == "Type":
        return finding.get("Types", [])
    if name == "SeverityProduct":
        severity_product = finding.get("Severity", {}).get("Product")
        return [severity_product] if severity_product is not None else []
    if name == "SeverityNormalized":
        severity_normalized = finding.get("Severity", {}).get("Normalized")
        return [severity_normalized] if severity_normalized is not None else []
    if name == "SeverityLabel":
        severity_label = finding.get("Severity", {}).get("Label")
        return [severity_label] if severity_label is not None else []

    return [finding[name]] if name in finding else []


@dataclass
class BotoStubCall:
    """Dataclass representing the inputs needed to stub a boto call."""

    method: str
    service_response: Any
    expected_params: Any | None = None


@contextmanager
def stub_boto_client(
    boto_session_client: BaseClient, calls: list[BotoStubCall]
) -> Generator[Stubber, None, None]:
    """Generate a context in which a boto client is stubbed with the specified calls.

    This function saves you from writing the boilerplate code to create a Stubber like:
    https://botocore.amazonaws.com/v1/documentation/api/latest/reference/stubber.html.

    Use like this:
    ```python
    boto_client = botocore.session.get_session().create_client("servicename")
    call = BotoStubCall(
        method="get_resources",
        service_response={"Resources": {"arn": "abc"}},
        expected_params={"Filters": "filters"},
    )
    with stub_boto_client(boto_client, [call]) as _:
        boto_client.get_resources(Filters="filters")
    ```

    Or the last part slightly more dynamically like this:
    ```python
    with stub_boto_client(boto_client, [call]) as _:
        getattr(boto_client, call.method)(**call.expected_params)
    ```

    Parameters
    ----------
    boto_session_client : BaseClient
        The boto session BaseClient that will be stubbed
    calls : list[botoStubCall]
        The list of botoStubCall instances representing the calls to add to the stubber

    Yields
    ------
    Generator[Stubber, None, None]
        A generator yielding a Stubber instance with the specified calls added.
        Usually not needed to be used directly,
        because the stubbing is active on the original session client within the context as a side effect.
    """
    stubber = Stubber(boto_session_client)
    for call in calls:
        stubber.add_response(**asdict(call))
    stubber.activate()
    try:
        yield stubber
    finally:
        stubber.deactivate()


def validate_call_params(
    boto_stub_calls: list[BotoStubCall],
    boto_session_client: BaseClient,
) -> None:
    """Validate boto call parameters by attempting to call the methods with the expected parameters in a stubbed context.

    Parameters
    ----------
    boto_stub_calls : list[BotoStubCall]
        The list of BotoStubCall instances representing the calls to validate
    boto_session_client : BaseClient
        The boto session BaseClient that will be used for validation

    Raises
    ------
    botocore.exceptions.ParamValidationError
        If any of the boto parameters contain invalid values
    """
    with stub_boto_client(
        boto_session_client,
        boto_stub_calls,
    ) as _:
        for response in boto_stub_calls:
            getattr(boto_session_client, response.method)(**response.expected_params)
