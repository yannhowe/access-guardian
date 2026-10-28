variable "name" {
  description = "Fix folder name. The role and function are ag-fix-<name>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", var.name))
    error_message = "name must be lowercase words separated by hyphens."
  }
}

variable "zip_path" {
  description = "Zip produced by esbuild. index.js at the root, handler index.handler."
  type        = string
}

variable "policy_json" {
  description = "Inline policy document from the fix folder policy.json."
  type        = string
}

variable "permissions_boundary_arn" {
  description = "ARN of ag-fix-boundary. Required. The module does not pick an account."
  type        = string
}
