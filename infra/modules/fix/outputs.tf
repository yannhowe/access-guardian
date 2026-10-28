output "function_name" {
  description = "Lambda the bot invokes."
  value       = aws_lambda_function.fix.function_name
}

output "role_name" {
  description = "Role attached to that Lambda."
  value       = aws_iam_role.fix.name
}
