"""Utilities for sechubman."""

import logging
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ParamValidationError
from botocore.stub import Stubber

LOGGER = logging.getLogger(__name__)


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


def validate_boto_call_params(
    boto_stub_calls: list[BotoStubCall],
    boto_session_client: BaseClient,
) -> bool:
    """Validate boto call parameters by attempting to call the methods with the expected parameters in a stubbed context.

    Parameters
    ----------
    boto_stub_calls : list[BotoStubCall]
        The list of BotoStubCall instances representing the calls to validate
    boto_session_client : BaseClient
        The boto session BaseClient that will be used for validation

    Returns
    -------
    bool
        True if all calls' parameters are valid, False otherwise
    """
    valid = False

    with stub_boto_client(
        boto_session_client,
        boto_stub_calls,
    ) as _:
        try:
            for response in boto_stub_calls:
                getattr(boto_session_client, response.method)(
                    **response.expected_params
                )
            valid = True
        except ParamValidationError as e:
            LOGGER.warning("Validation error: %s", e)

    return valid
