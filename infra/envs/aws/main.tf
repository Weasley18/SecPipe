# AWS profile: a private registry, an encrypted reports bucket, a budget alarm
# and three GitHub OIDC roles, one per job, each trusted by exactly one set of
# `sub` claims:
#
#   secpipe-tf-plan  read-only; PRs and main  (terraform plan, nightly drift)
#   secpipe-tf-apply manages this stack; only the aws-demo environment
#   secpipe-publish  pushes images/reports; only workflows on main
#
# No EKS or NAT gateway: both bill by the hour. The cluster stays on kind.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  repo_sub   = "repo:${var.github_repository}"
  # Created by infra/bootstrap; the apply role can only create roles under it.
  boundary_arn = "arn:aws:iam::${local.account_id}:policy/secpipe-ci-boundary"
  tags = {
    project    = "secpipe"
    owner      = var.owner
    managed-by = "terraform"
  }
}

module "ecr" {
  source              = "../../modules/ecr"
  name                = "secnotes"
  push_principal_arns = [module.publish_role.role_arn]
}

module "reports_bucket" {
  source           = "../../modules/reports-bucket"
  bucket_name      = var.reports_bucket_name
  owner            = var.owner
  retention_days   = 90
  writer_role_arns = [module.publish_role.role_arn]
}

module "budget" {
  source            = "../../modules/budget"
  monthly_limit_usd = var.monthly_budget_usd
  alert_emails      = var.budget_emails
}

module "plan_role" {
  source               = "../../modules/github-oidc-role"
  role_name            = "secpipe-tf-plan"
  github_repository    = var.github_repository
  create_oidc_provider = var.create_oidc_provider
  oidc_provider_arn    = var.existing_oidc_provider_arn
  allowed_subjects = [
    "${local.repo_sub}:pull_request",
    "${local.repo_sub}:ref:refs/heads/main",
  ]
  policy_json              = data.aws_iam_policy_document.plan.json
  permissions_boundary_arn = local.boundary_arn
}

module "apply_role" {
  source                   = "../../modules/github-oidc-role"
  role_name                = "secpipe-tf-apply"
  github_repository        = var.github_repository
  create_oidc_provider     = false
  oidc_provider_arn        = module.plan_role.oidc_provider_arn
  allowed_subjects         = ["${local.repo_sub}:environment:${var.deploy_environment}"]
  policy_json              = data.aws_iam_policy_document.apply.json
  permissions_boundary_arn = local.boundary_arn
}

module "publish_role" {
  source                   = "../../modules/github-oidc-role"
  role_name                = "secpipe-publish"
  github_repository        = var.github_repository
  create_oidc_provider     = false
  oidc_provider_arn        = module.plan_role.oidc_provider_arn
  allowed_subjects         = ["${local.repo_sub}:ref:refs/heads/main"]
  policy_json              = data.aws_iam_policy_document.publish.json
  permissions_boundary_arn = local.boundary_arn
}
