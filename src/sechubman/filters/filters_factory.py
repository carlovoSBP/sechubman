"""Convenient functionality to create AWS SecurityHub Finding Filters in a dynamic way."""

from enum import Enum
from typing import Any

from sechubman.utils import are_keys_in_dataclass_fields

from .date import DateFilter
from .filters_interface import Filter
from .number import NumberFilter
from .string import StringFilter


class AllFilters(Enum):
    """Enum representing all available AwsSecurityFindingFilters types."""

    NUMBER_FILTERS = NumberFilter
    DATE_FILTERS = DateFilter
    STRING_FILTERS = StringFilter


def match_to_filter_type(
    filter_dict: dict[str, Any],
) -> type[Filter]:
    """Match a filters dict to an AwsSecurityFindingFilters type.

    Parameters
    ----------
    filter_dict : dict[str, Any]
        The filters dict to match

    Returns
    -------
    type[Filter]
        The matched AwsSecurityFindingFilters type
    """
    return next(
        filter_type.value
        for filter_type in AllFilters
        if are_keys_in_dataclass_fields(filter_dict, filter_type.value.criterion_type)
    )


def create_filters(
    filters_dicts: list[dict[str, Any]],
) -> Filter:
    """Create an AwsSecurityFindingFilters instance from a list of filters dicts.

    Filters dicts must all correspond to the same AwsSecurityFindingFilters type.

    Parameters
    ----------
    filters_dicts : list[dict[str, Any]]
        The filters dicts to create the AwsSecurityFindingFilters instance from

    Returns
    -------
    Filter
        The created AwsSecurityFindingFilters instance
    """
    filter_type = match_to_filter_type(filters_dicts[0])
    return filter_type(
        criterions=tuple(
            filter_type.criterion_type(**comparison) for comparison in filters_dicts
        )
    )
