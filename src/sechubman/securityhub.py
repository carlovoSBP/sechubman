"""Data structures and algorithms as per SecurityHub filtering.

For more information, see:
https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFindingFilters.html.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Collection
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import partial
from typing import Any, ClassVar, TypeVar

from .utils import TimeRange


@dataclass
class AwsSecurityFindingFilter(ABC):
    """Abstract base class for AWS Security Finding Filter."""

    @abstractmethod
    def __post_init__(self) -> None:
        """Post-initialization must parse filter-specific input parameters."""

    @abstractmethod
    def match(self, finding_value: str) -> bool:
        """Check if a finding value matches this filter.

        Parameters
        ----------
        finding_value : str
            The value from the finding to compare against the filter

        Returns
        -------
        bool
            True if the finding_value matches the filter, False otherwise
        """


TFilter = TypeVar("TFilter", bound=AwsSecurityFindingFilter)


@dataclass
class AwsSecurityFindingFilters[TFilter: AwsSecurityFindingFilter](ABC):
    """Abstract base class for AWS Security Finding Filters."""

    finding_filters: tuple[TFilter, ...]
    combined_comparison: Callable = any

    @property
    @abstractmethod
    def filter_type(self) -> type:
        """The type of AwsSecurityFindingFilter this class relates to."""

    def match(self, finding_value: str) -> bool:
        """
        Check if a finding value matches the filters.

        Parameters
        ----------
        finding_value : str
            The value string from the finding to compare against the filters

        Returns
        -------
        bool
            True if the finding_value matches the combined filters, False otherwise
        """
        return self.combined_comparison(
            finding_filter.match(finding_value)
            for finding_filter in self.finding_filters
        )


def _str_prefix_ne_func(a: str, b: str) -> bool:
    return not str.startswith(a, b)


def _str_not_contains_func(a: str, b: str) -> bool:
    return not str.__contains__(a, b)


class StringComparisons(Enum):
    """The available string comparison operations linked to their functions.

    Parameters
    ----------
    value : str
        An available string comparison operation
    """

    EQUALS = partial(str.__eq__)
    PREFIX = partial(str.startswith)
    CONTAINS = partial(str.__contains__)
    NOT_EQUALS = partial(str.__ne__)
    PREFIX_NOT_EQUALS = partial(_str_prefix_ne_func)
    NOT_CONTAINS = partial(_str_not_contains_func)


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
class StringFilter(AwsSecurityFindingFilter):
    """Dataclass representing a SecurityHub StringFilter.

    Parameters
    ----------
    Comparison : str
        The comparison operation to use
    Value : str
        The value to compare against
    """

    Comparison: str
    Value: str

    def __post_init__(self) -> None:
        """Get the comparison function based on the Comparison attribute."""
        self.comparison_func = StringComparisons[self.Comparison].value

    def match(self, finding_value: str) -> bool:
        """Check if a string from a finding matches this string filter.

        Parameters
        ----------
        finding_value : str
            The string from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the filter, False otherwise
        """
        return self.comparison_func(finding_value, self.Value)


@dataclass
class DateFilters(AwsSecurityFindingFilters[DateFilter]):
    """Dataclass representing a collection of SecurityHub DateFilters to be applied on a single finding attribute.

    Parameters
    ----------
    date_filters : Generator[DateFilter]
        The DateFilter instances to hold against a single finding attribute
    """

    filter_type: ClassVar[type] = DateFilter
    finding_filters: tuple[DateFilter, ...]


@dataclass
class StringFilters(AwsSecurityFindingFilters[StringFilter]):
    """Dataclass representing a collection of SecurityHub StringFilters to be applied on a single finding attribute.

    Parameters
    ----------
    string_filters : tuple[StringFilter]
        The StringFilter instances to hold against a single finding attribute
    """

    filter_type: ClassVar[type] = StringFilter
    finding_filters: tuple[StringFilter, ...]

    def __post_init__(self) -> None:
        """Initialize the combined comparison function based on the types of string filters.

        All comparisons must be either positive or negative.
        Raise ValueError if mixed comparisons are found.
        """
        negatives = tuple(
            "NOT" in finding_filter.Comparison
            for finding_filter in self.finding_filters
        )
        if not any(negatives):
            self.combined_comparison = any
        elif all(negatives):
            self.combined_comparison = all
        else:
            msg = """
                Mixed positive and negative string filters are not supported:
                https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html
                """
            raise ValueError(msg)


class AllAwsSecurityFindingFilters(Enum):
    """Enum representing all available AwsSecurityFindingFilters types."""

    DATE_FILTERS = DateFilters
    STRING_FILTERS = StringFilters


def are_dict_keys_in_collection(dict_: dict, collection: Collection) -> bool:
    """Check if all keys in a dict are in a collection.

    Parameters
    ----------
    dict_ : dict
        The dict to check
    collection : Collection
        The collection to check against

    Returns
    -------
    bool
        True if all keys in the dict are in the collection, False otherwise
    """
    return all(key in collection for key in dict_)


def are_dict_keys_in_dataclass_fields(dict_: dict, dataclass_: type) -> bool:
    """Check if all keys in a dict are fields in a dataclass.

    Parameters
    ----------
    dict_ : dict
        The dict to check
    dataclass_ : type
        The dataclass to check against

    Returns
    -------
    bool
        True if all keys in the dict are fields in the dataclass, False otherwise
    """
    return are_dict_keys_in_collection(
        dict_, {field.name for field in fields(dataclass_)}
    )


def match_dict_to_aws_security_findings_filters(
    filters_dict: dict[str, Any],
) -> type[AwsSecurityFindingFilters]:
    """Match a filters dict to an AwsSecurityFindingFilters type.

    Parameters
    ----------
    filters_dict : dict[str, Any]
        The filters dict to match

    Returns
    -------
    type[AwsSecurityFindingFilters]
        The matched AwsSecurityFindingFilters type
    """
    return next(
        filters_type.value
        for filters_type in AllAwsSecurityFindingFilters
        if are_dict_keys_in_dataclass_fields(
            filters_dict, filters_type.value.filter_type
        )
    )


def create_aws_security_findings_filters_from_dicts(
    filters_dicts: list[dict[str, Any]],
) -> AwsSecurityFindingFilters:
    """Create an AwsSecurityFindingFilters instance from a list of filters dicts.

    Filters dicts must all correspond to the same AwsSecurityFindingFilters type.

    Parameters
    ----------
    filters_dicts : list[dict[str, Any]]
        The filters dicts to create the AwsSecurityFindingFilters instance from

    Returns
    -------
    AwsSecurityFindingFilters
        The created AwsSecurityFindingFilters instance
    """
    filters_type = match_dict_to_aws_security_findings_filters(filters_dicts[0])
    return filters_type(
        finding_filters=tuple(
            filters_type.filter_type(**comparison) for comparison in filters_dicts
        )
    )
