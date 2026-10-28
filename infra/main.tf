# One Lambda and one role per fix folder.
# A new fix adds its folder and one quoted name in fix_names.
# Build the zip first: scripts/build-fixes.sh

locals {
  fix_names = toset([
    "close-open-port",
    "restore-bucket-public-access-block",
    "remove-bucket-public-access-block",
  ])
}

module "fix" {
  source   = "./modules/fix"
  for_each = local.fix_names

  name                     = each.value
  zip_path                 = "${path.module}/../dist/fixes/${each.value}.zip"
  policy_json              = file("${path.module}/../src/fixes/${each.value}/policy.json")
  permissions_boundary_arn = var.permissions_boundary_arn
}

# One-off access grants. Terraform reads only this directory, so this module
# is what the apply workflow (terraform -chdir=infra) applies. State stays in
# the root S3 backend from -backend-config.
module "access_grants" {
  source = "./access-grants"
}
