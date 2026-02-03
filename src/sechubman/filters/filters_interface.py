"""The shared functionality of all AWS SecurityHub Finding Filters."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar


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
