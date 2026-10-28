# Security group CloudTrail intake on the default bus in the provider region.
#
# The rule and its one target already exist. The import blocks adopt them.
# Apply updates the rule pattern in place. It does not create a second rule.
#
# The connection ag-lead-webhook, the secret inside that connection, and the
# API destination ag-lead-webhook are not resources. Apply cannot create,
# update, rotate, or delete webhook auth. The connection is read by name.
# The destination ARN is built from the account on permissions_boundary_arn,
# the provider region, and the known destination id. It is not a second
# destination.

locals {
  # Plan and apply already pass permissions_boundary_arn. Its account is the
  # account Terraform runs in. Parsing it keeps that account out of git and
  # does not call AWS. sts:GetCallerIdentity is not required.
  sg_ingress_account_id = one(regex(
    "^arn:aws:iam::([0-9]{12}):policy/ag-fix-boundary$",
    var.permissions_boundary_arn,
  ))

  # Live target id on the rule. This is the target id, not the API destination id.
  sg_ingress_target_id = "ag-lead-webhook"

  eventbridge_to_ag_lead_role_arn = "arn:aws:iam::${local.sg_ingress_account_id}:role/ag-eventbridge-to-ag-lead"

  # Destination id of the hand-built API destination. Terraform does not manage
  # that destination and does not call events:DescribeApiDestination.
  lead_webhook_api_destination_arn = "arn:aws:events:${var.region}:${local.sg_ingress_account_id}:api-destination/ag-lead-webhook/6d9dbab1-d10f-4dd6-9951-f505036e202f"
}

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
    account = [local.sg_ingress_account_id]
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
  target_id      = local.sg_ingress_target_id
  arn            = local.lead_webhook_api_destination_arn
  role_arn       = local.eventbridge_to_ag_lead_role_arn

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
      condition     = var.region == "ap-southeast-1"
      error_message = "API destination ag-lead-webhook is in ap-southeast-1. var.region must stay ap-southeast-1 so the target ARN matches the live destination and apply does not rewrite the target."
    }

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
  id = "ag-cloudtrail-sg-ingress-to-lead/${local.sg_ingress_target_id}"
}
