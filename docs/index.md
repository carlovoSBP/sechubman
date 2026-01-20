# Welcome to sechubman

A library to help manage findings in AWS SecurityHub.
This library tries to stay as close to the boto3/API specifications as possible.
See [their documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html) for more information on low-level specifics.

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

client = boto3.client('securityhub')

rule = Rule(boto_securityhub_client=client, **rules[0])
rule.apply()
```
