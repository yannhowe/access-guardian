# Daily CloudTrail report. Read-only. This is not a fix and it is not in fix_names.
#
# The Lambda role allows three things:
# - cloudtrail:LookupEvents. LookupEvents has no resource ARN, so this one statement uses Resource "*".
# - secretsmanager:GetSecretValue on the xAI key secret and the Slack token secret.
# - logs:CreateLogStream and logs:PutLogEvents on this function's log group.
#   The trailing :* is the log stream name Lambda assigns at write time.
# Action names have no wildcard.
#
# The role does not use the fix permissions boundary. That boundary does not allow
# these read actions. The schedule role is separate. Its only action is
# lambda:InvokeFunction on this function, which is how EventBridge Scheduler runs it.

data "aws_secretsmanager_secret" "xai" {
  name = "platsec-xai-api-key"
}

resource "aws_secretsmanager_secret" "slack_bot_token" {
  name        = "ag-report-daily-slack-bot-token"
  description = "Bot token for the daily CloudTrail report Slack post. Set the value outside Terraform."
}

resource "aws_cloudwatch_log_group" "daily" {
  name              = "/aws/lambda/ag-report-daily"
  retention_in_days = 14
}

data "aws_iam_policy_document" "daily_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "daily" {
  name               = "ag-report-daily"
  assume_role_policy = data.aws_iam_policy_document.daily_trust.json
}

data "aws_iam_policy_document" "daily" {
  statement {
    sid       = "LookupCloudTrail"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid     = "ReadReportSecrets"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      data.aws_secretsmanager_secret.xai.arn,
      aws_secretsmanager_secret.slack_bot_token.arn,
    ]
  }

  statement {
    sid    = "WriteOwnLogStreams"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.daily.arn}:*"]
  }
}

resource "aws_iam_role_policy" "daily" {
  name   = "ag-report-daily"
  role   = aws_iam_role.daily.id
  policy = data.aws_iam_policy_document.daily.json
}

resource "aws_lambda_function" "daily" {
  function_name    = "ag-report-daily"
  role             = aws_iam_role.daily.arn
  runtime          = "nodejs20.x"
  handler          = "index.handler"
  filename         = "${path.module}/../dist/reports/daily.zip"
  source_code_hash = filebase64sha256("${path.module}/../dist/reports/daily.zip")
  timeout          = 60
  memory_size      = 256

  # SLACK_CHANNEL is the channel id for #platform-security.
  environment {
    variables = {
      XAI_SECRET_ID             = data.aws_secretsmanager_secret.xai.name
      SLACK_BOT_TOKEN_SECRET_ID = aws_secretsmanager_secret.slack_bot_token.name
      SLACK_CHANNEL             = "C0CDQ5V6RR6"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.daily,
    aws_iam_role_policy.daily,
  ]
}

data "aws_iam_policy_document" "daily_schedule_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "daily_schedule" {
  name               = "ag-report-daily-schedule"
  assume_role_policy = data.aws_iam_policy_document.daily_schedule_trust.json
}

data "aws_iam_policy_document" "daily_schedule" {
  statement {
    sid       = "InvokeDailyReport"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.daily.arn]
  }
}

resource "aws_iam_role_policy" "daily_schedule" {
  name   = "ag-report-daily-schedule"
  role   = aws_iam_role.daily_schedule.id
  policy = data.aws_iam_policy_document.daily_schedule.json
}

resource "aws_scheduler_schedule" "daily" {
  name                         = "ag-report-daily"
  schedule_expression          = "cron(0 0 * * ? *)"
  schedule_expression_timezone = "UTC"
  description                  = "Daily CloudTrail report at 08:00 SGT, which is 00:00 UTC."

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.daily.arn
    role_arn = aws_iam_role.daily_schedule.arn
    # dryRun defaults to true in the handler. This input is what makes the daily run post.
    input = jsonencode({
      hours  = 24
      dryRun = false
    })
  }
}
