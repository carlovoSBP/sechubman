"""SQS-triggered Lambda handler.

Each SQS record carries a single-rule rules document (as produced by
`sechubman.aws_lambda.trigger`): applies that rule against all currently matching Security Hub
findings.

Failures are logged per record but not re-raised, matching the queue's redrive policy, which
relies on the message becoming visible again after the visibility timeout rather than on the
Lambda invocation failing outright.
"""

import json
from typing import Any

from sechubman.aws_lambda.clients import get_securityhub_client
from sechubman.aws_lambda.logging import get_logger
from sechubman.aws_lambda.rules_backend import build_manager

LOGGER = get_logger()


@LOGGER.inject_lambda_context(log_event=True)
def lambda_handler(event: dict[str, Any], _context: object) -> None:
    """Apply the suppression rule carried by each SQS record to matching Security Hub findings.

    Parameters
    ----------
    event : dict[str, Any]
        The SQS event. Each `event["Records"]` entry's `body` is expected to be a JSON-encoded
        rules document with exactly one rule in its `Rules` list.
    _context : object
        The Lambda context object (unused).
    """
    for record in event.get("Records", []):
        rule = json.loads(record["body"])
        try:
            manager = build_manager(rule, get_securityhub_client())
            manager.get_and_update_all()
        except Exception:
            LOGGER.exception("Failed to process rule. Rule details: %s", rule)
