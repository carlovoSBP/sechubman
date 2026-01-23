"""Data structures and algorithms as per SecurityHub filtering.

For more information, see:
https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFindingFilters.html.
"""

from dataclasses import dataclass
from enum import Enum
from functools import partial


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
class StringFilter:
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
        self._comparison_func = StringComparisons[self.Comparison].value

    def match(self, finding_value: str) -> bool:
        """Check if a finding value matches this string filter.

        Parameters
        ----------
        finding_value : str
            The value from the finding to compare against the filter

        Returns
        -------
        bool
            True if the finding_value matches the filter, False otherwise
        """
        return self._comparison_func(finding_value, self.Value)


@dataclass
class StringFilters:
    """Dataclass representing a collection of SecurityHub StringFilters to be applied on a single finding attribute.

    Parameters
    ----------
    string_filters : list[StringFilter]
        The StringFilter instances to hold against a single finding attribute
    """

    string_filters: list[StringFilter]

    def __post_init__(self) -> None:
        """Initialize the combined comparison function based on the types of string filters.

        All comparisons must be either positive or negative.
        Raise ValueError if mixed comparisons are found.
        """
        negatives = tuple(
            "NOT" in string_filter.Comparison for string_filter in self.string_filters
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

    def match(self, finding_value: str) -> bool:
        """
        Check if a finding value matches the string filters.

        Parameters
        ----------
        finding_value : str
            The value from the finding to compare against the filters

        Returns
        -------
        bool
            True if the finding_value matches the combined filters, False otherwise
        """
        return self.combined_comparison(
            string_filter.match(finding_value) for string_filter in self.string_filters
        )
