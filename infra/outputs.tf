output "function_names" {
  description = "Lambda function name for each fix."
  value       = { for name, fix in module.fix : name => fix.function_name }
}
