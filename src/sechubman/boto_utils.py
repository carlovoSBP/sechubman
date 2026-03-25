"""Boto-related utilities for sechubman."""

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from botocore.client import BaseClient
from botocore.stub import Stubber

# This only contains the special cases that are still relevant for the current finding format
# The network block and some severity members in the finding format are retired
# Sample member is also not included, because it is unlikely to be used in production
SPECIAL_CASES = {
    "Type": "Types[]",
    "SeverityLabel": "Severity.Label",
    "RecommendationText": "Remediation.Recommendation.Text",
    "MalwareName": "Malware[].Name",
    "MalwareType": "Malware[].Type",
    "MalwarePath": "Malware[].Path",
    "MalwareState": "Malware[].State",
    "ProcessName": "Process[].Name",
    "ProcessPath": "Process[].Path",
    "ProcessPid": "Process[].Pid",
    "ProcessParentPid": "Process[].ParentPid",
    "ProcessLaunchedAt": "Process[].LaunchedAt",
    "ProcessTerminatedAt": "Process[].TerminatedAt",
    "ThreatIntelIndicatorType": "ThreatIntelIndicators[].Type",
    "ThreatIntelIndicatorValue": "ThreatIntelIndicators[].Value",
    "ThreatIntelIndicatorCategory": "ThreatIntelIndicators[].Category",
    "ThreatIntelIndicatorLastObservedAt": "ThreatIntelIndicators[].LastObservedAt",
    "ThreatIntelIndicatorSource": "ThreatIntelIndicators[].Source",
    "ThreatIntelIndicatorSourceUrl": "ThreatIntelIndicators[].SourceUrl",
    # resource block todo
    "ComplianceStatus": "Compliance.Status",
    "WorkflowStatus": "Workflow.Status",
    "RelatedFindingsProductArn": "RelatedFindings[].ProductArn",
    "RelatedFindingsId": "RelatedFindings[].Id",
    "NoteText": "Note.Text",
    "NoteUpdatedAt": "Note.UpdatedAt",
    "NoteUpdatedBy": "Note.UpdatedBy",
    "FindingProviderFieldsConfidence": "FindingProviderFields.Confidence",
    "FindingProviderFieldsCriticality": "FindingProviderFields.Criticality",
    "FindingProviderFieldsRelatedFindingsId": "FindingProviderFields.RelatedFindings[].Id",
    "FindingProviderFieldsRelatedFindingsProductArn": "FindingProviderFields.RelatedFindings[].ProductArn",
    "FindingProviderFieldsSeverityLabel": "FindingProviderFields.Severity.Label",
    "FindingProviderFieldsSeverityOriginal": "FindingProviderFields.Severity.Original",
    "FindingProviderFieldsTypes": "FindingProviderFields.Types[]",
    "ComplianceSecurityControlId": "Compliance.SecurityControlId",
    "ComplianceAssociatedStandardsId": "Compliance.AssociatedStandards[].StandardsId",
    "VulnerabilitiesExploitAvailable": "Vulnerabilities[].ExploitAvailable",
    "VulnerabilitiesFixAvailable": "Vulnerabilities[].FixAvailable",
    "ComplianceSecurityControlParametersName": "Compliance.SecurityControlParameters[].Name",
    "ComplianceSecurityControlParametersValue": "Compliance.SecurityControlParameters[].Value[]",
    "ResourceApplicationName": "Resources[].ApplicationName",
    "ResourceApplicationArn": "Resources[].ApplicationArn",
}


def _get_values_by_path(finding: dict, path: str) -> list[Any]:
    """Resolve a simple dot-path with optional [] list traversal markers."""

    def as_list(value: object) -> list[Any]:
        return value if isinstance(value, list) else [value]

    nodes: list[Any] = [finding]
    for segment in path.split("."):
        expand_list = segment.endswith("[]")
        key = segment[:-2] if expand_list else segment
        next_nodes: list[Any] = []

        for node in nodes:
            for candidate in as_list(node):
                if not isinstance(candidate, dict):
                    continue
                value = candidate.get(key)
                if value is None:
                    continue

                if expand_list:
                    next_nodes.extend(as_list(value))
                else:
                    next_nodes.append(value)

        nodes = next_nodes
        if not nodes:
            break

    return [node for node in nodes if node is not None]


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
    if name in SPECIAL_CASES:
        return _get_values_by_path(finding, SPECIAL_CASES[name])

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
