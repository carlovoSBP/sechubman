"""Utilities for sechubman."""

import logging
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ParamValidationError
from botocore.stub import Stubber

LOGGER = logging.getLogger(__name__)


def is_empty_or_valid(
    candidate: object | None,
    reference: object,
    validator: Callable[..., bool],
) -> bool:
    """Check if 'candidate' is falsy or whether it passes the 'validator' check against 'reference'."""
    return not candidate or validator(candidate, reference)


def parse_timestamp_str_if_set(timestamp_str: str) -> datetime | None:
    """Parse an ISO format timestamp string to a datetime object if it is set.

    Parameters
    ----------
    timestamp_str : str
        The timestamp string in ISO format

    Returns
    -------
    datetime | None
        The parsed datetime object if the string is set, None otherwise
    """
    return datetime.fromisoformat(timestamp_str) if timestamp_str else None


@dataclass
class TimeRange:
    """Dataclass representing a time range with optional start or end."""

    start: datetime | None = None
    end: datetime | None = None

    def __post_init__(self) -> None:
        """Validate that at least one of start or end is set.

        Raises
        ------
        ValueError
            If neither start nor end is set.
        """
        if not self.start and not self.end:
            msg = "At least one of start or end must be set."
            raise ValueError(msg)

    @staticmethod
    def from_str(start_str: str, end_str: str) -> "TimeRange":
        """Create a TimeRange instance from ISO format timestamp strings.

        Parameters
        ----------
        start_str : str
            The start timestamp string in ISO format
        end_str : str
            The end timestamp string in ISO format

        Returns
        -------
        TimeRange
            The created TimeRange instance
        """
        start = parse_timestamp_str_if_set(start_str)
        end = parse_timestamp_str_if_set(end_str)
        return TimeRange(start=start, end=end)

    def is_timestamp_in_range(self, timestamp: datetime) -> bool:
        """Check if a datetime timestamp is within the time range.

        Parameters
        ----------
        timestamp : datetime
            The datetime timestamp to check

        Returns
        -------
        bool
            True if the timestamp is within the range, False otherwise
        """
        return is_empty_or_valid(
            timestamp, self.start, datetime.__ge__
        ) and is_empty_or_valid(timestamp, self.end, datetime.__le__)

    def is_timestamp_str_in_range(self, timestamp_str: str) -> bool:
        """Check if a timestamp string is within the time range.

        Parameters
        ----------
        timestamp_str : str
            The timestamp string in ISO format to check

        Returns
        -------
        bool
            True if the timestamp string is within the time range, False otherwise
        """
        timestamp = datetime.fromisoformat(timestamp_str)
        return self.is_timestamp_in_range(timestamp)


def get_finding_values_from_boto_argument(finding: dict, name: str) -> list[str]:
    """Get the values if a finding for a given boto argument name.

    Some arguments in:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/client/get_findings.html
    do not directly map to finding fields as per:
    https://docs.amazonaws.cn/en_us/securityhub/latest/userguide/securityhub-findings-format.html
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
