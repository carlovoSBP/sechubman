"""Deprecated: use `sechubman.aws_lambda.scheduled` instead.

Kept as a backwards-compatible re-export so that a Lambda already configured with the handler
path `sechubman.aws_lambda_handler.lambda_handler` (as produced by sechubman 1.1.x) keeps working
after upgrading.
"""

from sechubman.aws_lambda.scheduled import lambda_handler

__all__ = ["lambda_handler"]
