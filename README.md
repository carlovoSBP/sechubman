# sechubman

A library to help manage findings in AWS Security Hub through declarative, boto3-shaped
suppression rules.

Full documentation, including rule syntax and code examples, is available at
[carlovosbp.github.io/sechubman](https://carlovosbp.github.io/sechubman/).

## Features

- Rules map directly onto the `get_findings`/`batch_update_findings` boto3 API, so anything the
  Security Hub API supports as a filter or update is available without extra abstraction.
- A `Manager` lets you set shared defaults (filters, updates, note handling) once and have
  individual rules override only what differs.
- Regex matching on string fields (`ExtraFeatures.RegexStringFilters`), not natively supported by
  the API, is layered on top.
- JSON-formatted suppression notes (`ExtraFeatures.NoteTextConfig`) merge into existing
  JSON-formatted note metadata, e.g. to coexist with a ticketing system's own note fields.
- Ready-made AWS Lambda handlers (`sechubman[lambda]`) for running suppression on a schedule, or
  as an event-driven pipeline reacting to new findings and to rules-file changes.

## Installation

```bash
uv add sechubman
# or, with the AWS Lambda handlers:
uv add 'sechubman[lambda]'
```

```bash
pip install sechubman
# or
pip install 'sechubman[lambda]'
```

## Quick start

```python
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

See the [documentation](https://carlovosbp.github.io/sechubman/) for the full rule syntax,
the `Manager` API for managing many rules at once, and how to run sechubman as an AWS Lambda.

## Developing further

> Development flow as [Paleofuturistic Python](https://github.com/schubergphilis/paleofuturistic_python)

Prerequisite: [uv](https://docs.astral.sh/uv/)

### Setup

- Fork and clone this repository.
- Download additional dependencies: `uv sync --all-extras --dev`
- Optional: validate the setup with `uv run python -m unittest`

### Workflow

- Download dependencies (if you need any): `uv add some_lib_you_need`
- Develop (optional, tinker: `uvx --with-editable . ptpython`)
- QA:
    - Format: `uv run ruff format`
    - Lint: `uv run ruff check`
    - Type check: `uv run mypy`
    - Test: `uv run python -m unittest`
- Build (to validate it works): `uv build`
- Review documentation updates: `uv run mkdocs serve`
- Make a pull request.
