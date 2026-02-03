"""Convenient functionality to create AWS SecurityHub Finding Filters in a dynamic way."""

from enum import Enum
from typing import Any

from sechubman.utils import are_dict_keys_in_dataclass_fields

from .date import DateFilters
from .filters_interface import AwsSecurityFindingFilters
from .string import StringFilters


class AllAwsSecurityFindingFilters(Enum):
    """Enum representing all available AwsSecurityFindingFilters types."""

    DATE_FILTERS = DateFilters
    STRING_FILTERS = StringFilters


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
