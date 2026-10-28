# Security group CloudTrail intake on the default bus in the provider region.
#
# The rule and its one target already exist. The import blocks adopt them.
# Apply updates the rule pattern in place. It does not create a second rule.
#
# The connection ag-lead-webhook, the secret inside that connection, and the
# API destination ag-lead-webhook are not resources. Apply cannot create,
# update, rotate, or delete webhook auth. The connection is read by name.
# The destination ARN is a variable Yann fills. It is not invented here.

data "aws_cloudwatch_event_connection" "ag_lead_webhook" {
  name = "ag-lead-webhook"
}

resource "aws_cloudwatch_event_rule" "sg_ingress" {
  name           = "ag-cloudtrail-sg-ingress-to-lead"
  event_bus_name = "default"
  event_pattern = jsonencode({
    source = ["aws.ec2"]
    "detail-type" = [
      "AWS API Call via CloudTrail",
    ]
    account = [var.ag_cloudtrail_sg_ingress_account_id]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules",
      ]
      errorCode = [{ exists = false }]
    }
  })

  lifecycle {
    prevent_destroy = true
    # Description and tags are already on the live rule and are not in this repo.
    # Leave them. The only intended change is event_pattern.
    ignore_changes = [description, tags, tags_all]
  }
}

resource "aws_cloudwatch_event_target" "sg_ingress" {
  rule           = aws_cloudwatch_event_rule.sg_ingress.name
  event_bus_name = aws_cloudwatch_event_rule.sg_ingress.event_bus_name
  target_id      = var.ag_cloudtrail_sg_ingress_target_id
  arn            = var.ag_lead_webhook_api_destination_arn
  role_arn       = var.ag_eventbridge_to_ag_lead_role_arn

  lifecycle {
    prevent_destroy = true
    # The live target already has an input transformer and a retry policy.
    # Those exact strings are not in this repo. docs/intake.md describes them.
    # Ignoring them keeps apply from rewriting delivery. Do not drop this
    # until the live template has been copied here exactly.
    ignore_changes = [
      input,
      input_path,
      input_transformer,
      retry_policy,
      dead_letter_config,
      http_target,
    ]

    precondition {
      condition = (
        data.aws_cloudwatch_event_connection.ag_lead_webhook.authorization_type == "API_KEY" &&
        data.aws_cloudwatch_event_connection.ag_lead_webhook.secret_arn != ""
      )
      error_message = "Connection ag-lead-webhook must stay an API key connection with its existing secret. Terraform does not create, update, or rotate that connection or its secret."
    }
  }
}

import {
  to = aws_cloudwatch_event_rule.sg_ingress
  id = "ag-cloudtrail-sg-ingress-to-lead"
}

import {
  to = aws_cloudwatch_event_target.sg_ingress
  id = "ag-cloudtrail-sg-ingress-to-lead/${var.ag_cloudtrail_sg_ingress_target_id}"
}
