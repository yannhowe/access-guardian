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
