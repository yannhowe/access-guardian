data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fix" {
  name                 = "ag-fix-${var.name}"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "fix" {
  name   = "ag-fix-${var.name}"
  role   = aws_iam_role.fix.id
  policy = var.policy_json
}

# Terraform creates the log group, so the function only needs to write streams.
resource "aws_iam_role_policy" "logs" {
  name = "logs"
  role = aws_iam_role.fix.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteStreams"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.fix.arn}:*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "fix" {
  name              = "/aws/lambda/ag-fix-${var.name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "fix" {
  function_name    = "ag-fix-${var.name}"
  role             = aws_iam_role.fix.arn
  runtime          = "nodejs20.x"
  handler          = "index.handler"
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  timeout          = 30
  memory_size      = 256

  depends_on = [
    aws_cloudwatch_log_group.fix,
    aws_iam_role_policy.fix,
    aws_iam_role_policy.logs,
  ]
}
