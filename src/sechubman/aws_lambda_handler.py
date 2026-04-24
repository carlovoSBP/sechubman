"""AWS Lambda handler for Security Hub findings suppression using sechubman in automatic mode."""

from pathlib import Path

from aws_lambda_powertools import Logger
from aws_lambda_powertools.logging import utils
from boto3 import client
from yaml import safe_load

from sechubman import Manager

LOGGER = Logger()
utils.copy_config_to_registered_loggers(source_logger=LOGGER)


def _get_rules(rules_path: str = "rules.yaml") -> dict:
    with Path(rules_path).open() as file:
        return safe_load(file)


SECURITYHUB_CLIENT = client("securityhub")


def _get_manager(rules: dict) -> Manager:
    return (
        Manager(**rules["ManagerConfig"], client=SECURITYHUB_CLIENT)
        if "ManagerConfig" in rules
        else Manager(client=SECURITYHUB_CLIENT)
    )


@LOGGER.inject_lambda_context(log_event=True)
def lambda_handler(_event: dict, _context: object) -> None:
    """Lambda handler to apply suppression rules to Security Hub findings."""
    rules = _get_rules()
    manager = _get_manager(rules)

    manager.set_rules(rules["Rules"])
    manager.get_and_update_all()
