# Welcome to sechubman

A library to help manage findings in AWS SecurityHub.
This library tries to stay as close to the boto3/API specifications as possible.
See [their documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html) for more information on low-level specifics.

Some quirks about the API worth mentioning for the usability of this library:

- This library uses the original `get_findings` boto3/API call, because it is the most versatile one.
  As such, string filters can only be `"EQUALS"|"PREFIX"|"NOT_EQUALS"|"PREFIX_NOT_EQUALS"`
  and map filters can only be `"EQUALS"|"NOT_EQUALS"`.
  See [the string filter API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html)
  and [the map filter API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_MapFilter.html)
  for more information.
- The boto3/API arguments don't always exactly match with finding fields.
  For example, the finding field `{"Severity":{"Label":"string"}}` becomes simply `SeverityLabel` as a filter field.
  Compare [the API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html#API_GetFindings_RequestBody)
  with [the finding specs](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
  for more details.
- The `Cidr` attribute of the [IpFilter](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_IpFilter.html) works like a [StringFilter](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html) with `Value` set to the value for `Cidr` and `Comparison` set to `EQUALS`.

Things worth noting about the library itself.

- To make big rule files a little smaller and more readable rules can be create via a rule manager.
  The rule manager can have a default config for all rules created by it.
- Individual rules can still override the defaults set by the manager.
- All string filter fields can also filter values on regexes when set under `ExtraFeatures` > `RegexStringFilters`.
  This is not supported by the API, so it always happens in the logic of this library.
  See the code examples below on how to use it.
- Setting `jsonUpdate` mode under `ExtraFeatures` > `NoteTextConfig` enables a more structured way of storing notes.
  It allows for note preservation from other processes by merging existing JSON formatted note metadata.
  This requires setting a key under which to store the data in the JSON object.
  This is particularly useful when integrating with ticketing systems or when multiple teams manage findings.
  When a note is empty, this mode will create a new JSON note like: `{"Note":"Suppress SSM.7 findings"}`.
  Existing notes in plain text (non-JSON-formatted) will be overwritten, the previous note will be captured in the logs.
  When there is an existing JSON-formatted note, this mode will update only the key it manages in that note like: `{"jiraIssue":"PROJ-123","Note":"Suppress SSM.7 findings"}`.
  See the code examples below on how to activate it.
- Often the note is the only specific input to what you want to update with a rule.
  To trim some boilerplate config per rule, the feature `QuickNote` can be used.
  See the code examples below on how to use it.

## Example usage

```yaml
Rules:
- Filters:
    Region:
    - Value: eu-west-1
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
  ExtraFeatures:
    RegexStringFilters:
      ResourceId:
      - .*-dev$
      - .*-test$
      Description:
      - .*non-critical.*
    NoteTextConfig:
      Mode: jsonUpdate
      Key: suppressionReason
```

```Python
from pathlib import Path

import boto3
import yaml

from sechubman import Rule


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)["Rules"]

client = boto3.client("securityhub")

rule = Rule(**rules[0], client=client)
rule.get_and_update()
```

### Condensing big rule sets

```yaml
ManagerConfig:
  DefaultRuleInput:
    Filters:
      WorkflowStatus:
      - Value: NEW
        Comparison: EQUALS
      - Value: NOTIFIED
        Comparison: EQUALS
    UpdatesToFilteredFindings:
      Workflow:
        Status: SUPPRESSED
      Note:
        UpdatedBy: sechubman
  ExtraFeatures:
    NoteTextConfig:
      Mode: jsonUpdate
      Key: suppressionReason
Rules:
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-sechubman
      Comparison: EQUALS
  UpdatesToFilteredFindings:
    Note:
      Text: Test
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-sechubman-2
      Comparison: EQUALS
  ExtraFeatures:
    NoteTextConfig:
      Mode: plaintext
    QuickNote: Test-2
```

```Python
from pathlib import Path

import boto3
import yaml

from sechubman import Manager


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)

client = boto3.client("securityhub")

manager = Manager(**rules["ManagerConfig"], client=client)
manager.set_rules(rules["Rules"])
manager.get_and_update_all()
```
