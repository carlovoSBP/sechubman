# Welcome to sechubman

A library to help manage findings in AWS Security Hub.
This library tries to stay as close to the boto3/API specifications as possible.
See [their documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html) for more information on low-level specifics.

## Example usage

```yaml
Rules:
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-security
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

import yaml

from sechubman import Rule


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)["Rules"]

rule = Rule(**rules[0])
rule.apply()
```
