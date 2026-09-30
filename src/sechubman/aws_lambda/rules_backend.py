"""Load suppression rules for AWS Lambda use, and build a sechubman Manager from them."""

import os
from pathlib import Path
from typing import Any

from botocore.client import BaseClient

from sechubman import Manager

try:
    from yaml import safe_load
except ImportError as error:
    msg = (
        "pyyaml is required to use sechubman.aws_lambda handlers. "
        "Install it with the 'lambda' extra, e.g. `uv add 'sechubman[lambda]'` "
        "or `pip install 'sechubman[lambda]'`."
    )
    raise ImportError(msg) from error

ALLOWED_MANAGER_CONFIG_KEYS = {"DefaultRuleInput"}


def load_rules(s3_client: BaseClient | None = None) -> dict[str, Any]:
    """Load the rules document, from S3 if configured, otherwise from a local file.

    If both the `S3_BUCKET_NAME` and `S3_OBJECT_NAME` environment variables are set, the rules
    document is loaded from that S3 object. Otherwise, it is loaded from the local file at
    `RULES_PATH` (defaults to `rules.yaml`).

    Parameters
    ----------
    s3_client : BaseClient, optional
        The boto3 S3 client to use when loading rules from S3. Only used (and required) when
        `S3_BUCKET_NAME` and `S3_OBJECT_NAME` are both set. Accepting it as a parameter, rather
        than creating one internally, keeps this function free of AWS calls in unit tests.

    Returns
    -------
    dict[str, Any]
        The parsed rules document, expected to contain a top-level `Rules` key and optionally a
        `ManagerConfig` key.

    Raises
    ------
    ValueError
        If S3 loading is configured but no `s3_client` was provided.
    """
    bucket_name = os.environ.get("S3_BUCKET_NAME")
    object_name = os.environ.get("S3_OBJECT_NAME")

    if bucket_name and object_name:
        if s3_client is None:
            msg = (
                "S3_BUCKET_NAME and S3_OBJECT_NAME are set, but no s3_client was provided "
                "to load_rules()."
            )
            raise ValueError(msg)
        response = s3_client.get_object(Bucket=bucket_name, Key=object_name)
        return safe_load(response["Body"].read())

    rules_path = os.environ.get("RULES_PATH", "rules.yaml")
    with Path(rules_path).open() as file:
        return safe_load(file)


def build_manager(rules: dict[str, Any], client: BaseClient) -> Manager:
    """Build a Manager with its rules registered from a parsed rules document.

    Parameters
    ----------
    rules : dict[str, Any]
        The parsed rules document, as returned by `load_rules`. Must contain a top-level `Rules`
        key, and may contain a `ManagerConfig` key with a `DefaultRuleInput` sub-key.
    client : BaseClient
        The boto3 Security Hub client to use for the manager and its rules.

    Returns
    -------
    Manager
        A Manager with its rules already registered via `Manager.set_rules`.

    Raises
    ------
    ValueError
        If the rules document has no top-level `Rules` key, or if `ManagerConfig` contains
        keys other than `DefaultRuleInput` (most commonly caused by putting `ExtraFeatures`
        next to, rather than inside, `DefaultRuleInput`).
    """
    if "Rules" not in rules:
        msg = "The rules document must contain a top-level 'Rules' key."
        raise ValueError(msg)

    manager_config = rules.get("ManagerConfig", {})
    unknown_keys = set(manager_config) - ALLOWED_MANAGER_CONFIG_KEYS
    if unknown_keys:
        msg = (
            f"Unsupported 'ManagerConfig' key(s): {sorted(unknown_keys)}. "
            f"Allowed keys are: {sorted(ALLOWED_MANAGER_CONFIG_KEYS)}. "
            "'ExtraFeatures' and other rule fields belong inside 'DefaultRuleInput', "
            "not next to it."
        )
        raise ValueError(msg)

    manager = Manager(**manager_config, client=client)
    manager.set_rules(rules["Rules"])
    return manager
