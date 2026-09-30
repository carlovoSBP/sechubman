# AWS Lambda handlers

Requires the `lambda` extra (`sechubman[lambda]`). See "Running in AWS Lambda" on the home page
for the deployment contract (triggers, environment variables, IAM permissions).

## Handlers

::: sechubman.aws_lambda.scheduled.lambda_handler

::: sechubman.aws_lambda.events.lambda_handler

::: sechubman.aws_lambda.trigger.lambda_handler

::: sechubman.aws_lambda.worker.lambda_handler

## Rules loading

::: sechubman.aws_lambda.rules_backend.load_rules

::: sechubman.aws_lambda.rules_backend.build_manager
