variable "region" {
  description = "Region for the fix Lambdas and their log groups."
  type        = string
  default     = "ap-southeast-1"
}

variable "permissions_boundary_arn" {
  description = "ARN of the ag-fix-boundary policy. Pass it at plan time. There is no default, and this file does not name an account."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:policy/ag-fix-boundary$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be the ag-fix-boundary policy ARN."
  }
}

variable "ag_cloudtrail_sg_ingress_account_id" {
  description = "12-digit account id already on rule ag-cloudtrail-sg-ingress-to-lead. Pass the live value at plan time. Do not commit it. There is no default."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.ag_cloudtrail_sg_ingress_account_id))
    error_message = "ag_cloudtrail_sg_ingress_account_id must be the 12-digit account id already on the live rule."
  }
}

variable "ag_cloudtrail_sg_ingress_target_id" {
  description = "EventBridge target id already on rule ag-cloudtrail-sg-ingress-to-lead. This is not the API destination id. Pass the live target id at plan time. There is no default."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,64}$", var.ag_cloudtrail_sg_ingress_target_id))
    error_message = "ag_cloudtrail_sg_ingress_target_id must be the live target id: 1 to 64 letters, digits, dots, underscores, or hyphens."
  }
}

variable "ag_eventbridge_to_ag_lead_role_arn" {
  description = "ARN of the existing role ag-eventbridge-to-ag-lead, the role already on the rule target. Pass the live ARN at plan time. Do not invent it. There is no default."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/ag-eventbridge-to-ag-lead$", var.ag_eventbridge_to_ag_lead_role_arn))
    error_message = "ag_eventbridge_to_ag_lead_role_arn must be the ARN of role ag-eventbridge-to-ag-lead."
  }
}

variable "ag_lead_webhook_api_destination_arn" {
  description = "ARN of the existing API destination ag-lead-webhook. The destination id is 6d9dbab1-d10f-4dd6-9951-f505036e202f. Pass the live ARN at plan time. Do not invent it. There is no default. Terraform does not manage this destination."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:events:ap-southeast-1:[0-9]{12}:api-destination/ag-lead-webhook/6d9dbab1-d10f-4dd6-9951-f505036e202f$", var.ag_lead_webhook_api_destination_arn))
    error_message = "ag_lead_webhook_api_destination_arn must be the ap-southeast-1 ARN of API destination ag-lead-webhook with id 6d9dbab1-d10f-4dd6-9951-f505036e202f."
  }
}
