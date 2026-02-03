"""AWS SecurityHub Finding Date Filters."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from sechubman.utils import TimeRange

from .filters_interface import AwsSecurityFindingFilter, AwsSecurityFindingFilters


@dataclass
class DateFilter(AwsSecurityFindingFilter):
    """Dataclass representing a SecurityHub DateFilter.

    Parameters
    ----------
    DateRange : dict[str, str]
        The comparison operation to use
    End : str
        The value to compare against
    Start : str
        The value to compare against
    """

    DateRange: dict[str, str] = field(default_factory=dict)
    End: str = ""
    Start: str = ""

    def _now_utc(self) -> datetime:
        """Having this method allows for easier mocking in tests."""
        return datetime.now(UTC)

    def __post_init__(self) -> None:
        """Initialize the date filter on DateRange or Start/End."""
        self.time_range = (
            TimeRange(
                self._now_utc() - timedelta(days=int(self.DateRange["Value"])),
                None,
            )
            if self.DateRange
            else TimeRange.from_str(self.Start, self.End)
        )

    def match(self, finding_value: str) -> bool:
        """Check if a datetime string from a finding matches this string filter.

        Parameters
        ----------
        finding_value : str
            The string from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the filter, False otherwise
        """
        return self.time_range.is_timestamp_str_in_range(finding_value)


@dataclass
class DateFilters(AwsSecurityFindingFilters[DateFilter]):
    """Dataclass representing a collection of SecurityHub DateFilters to be applied on a single finding attribute."""

    filter_type: ClassVar[type] = DateFilter
    finding_filters: tuple[DateFilter, ...]
