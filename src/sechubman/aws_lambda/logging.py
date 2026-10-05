"""Shared Lambda logging setup, built on aws-lambda-powertools.

aws-lambda-powertools is an optional dependency (the 'lambda' extra), so importing this module
without it installed raises a clear, actionable error instead of a bare ModuleNotFoundError.
"""

try:
    from aws_lambda_powertools import Logger
    from aws_lambda_powertools.logging import utils
except ImportError as error:
    msg = (
        "aws-lambda-powertools is required to use sechubman.aws_lambda handlers. "
        "Install it with the 'lambda' extra, e.g. `uv add 'sechubman[lambda]'` "
        "or `pip install 'sechubman[lambda]'`."
    )
    raise ImportError(msg) from error


def get_logger() -> Logger:
    """Create a powertools Logger and propagate its configuration to other registered loggers.

    The service name is taken from the `POWERTOOLS_SERVICE_NAME` environment variable, as usual
    for aws-lambda-powertools.

    Returns
    -------
    Logger
        A ready-to-use powertools Logger.
    """
    logger = Logger()
    utils.copy_config_to_registered_loggers(source_logger=logger)
    return logger
