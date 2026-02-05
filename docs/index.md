# Welcome to sechubman

A library to help manage findings in AWS SecurityHub.
This library tries to stay as close to the boto3/API specifications as possible.
See [their documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html) for more information on low-level specifics.

Some quirks about the API worth mentioning for the usability of this library:

- This library uses the original `get_findings` boto3/API call, because it is the most versatile one.
  As such, string filters can only be: `"EQUALS"|"PREFIX"|"NOT_EQUALS"|"PREFIX_NOT_EQUALS"`.
  See [the API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html) for more information.
- The boto3/API arguments don't always exactly match with finding fields.
  For example, the finding field `{"Severity":{"Label":"string"}}` becomes simply `SeverityLabel` as a filter field.
  Compare [the API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html#API_GetFindings_RequestBody)
  with [the finding specs](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
  for more details.

## Example usage

```yaml
Rules:
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-sechubman
      Comparison: EQUALS
    WorkflowStatus:
    - Value: NEW
      Comparison: EQUALS
  UpdatesToFilteredFindings:
    Workflow:
      Status: SUPPRESSED
    Note:
      Text: Test
      UpdatedBy: sechubman
```

```Python
from pathlib import Path

import boto3
import yaml

from sechubman import Rule


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)["Rules"]

client = boto3.client("securityhub")

rule = Rule(boto_securityhub_client=client, **rules[0])
rule.apply()
```
