# Least-privilege policies for the three CI roles. Resource ARNs are built from
# names so every statement is scoped to this stack's resources.

locals {
  partition     = "aws"
  region_prefix = "arn:${local.partition}:%s:${var.region}:${local.account_id}"

  state_bucket_arn = "arn:${local.partition}:s3:::${var.state_bucket}"
  state_object_arn = "${local.state_bucket_arn}/${var.state_key}"
  state_lock_arn   = "${local.state_object_arn}.tflock"

  reports_bucket_arn = "arn:${local.partition}:s3:::${var.reports_bucket_name}"
  ecr_repository_arn = "${format(local.region_prefix, "ecr")}:repository/secnotes"
  kms_keys_arn       = "${format(local.region_prefix, "kms")}:key/*"
  kms_aliases_arn    = "${format(local.region_prefix, "kms")}:alias/secpipe-*"
  budgets_arn        = "arn:${local.partition}:budgets::${local.account_id}:budget/secpipe-*"
  roles_arn          = "arn:${local.partition}:iam::${local.account_id}:role/secpipe-*"
  oidc_provider_arn  = "arn:${local.partition}:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"

  # Read access shared by plan and apply (terraform refresh).
  read_statements = {
    StateList = {
      actions   = ["s3:ListBucket"]
      resources = [local.state_bucket_arn]
    }
    StateRead = {
      actions   = ["s3:GetObject"]
      resources = [local.state_object_arn]
    }
    StateLock = {
      actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      resources = [local.state_lock_arn]
    }
    StateKey = {
      actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources = [var.state_kms_key_arn]
    }
    ReadRoles = {
      actions = [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:GetOpenIDConnectProvider",
      ]
      resources = [local.roles_arn, local.oidc_provider_arn]
    }
    ReadRegistry = {
      actions = [
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:ListTagsForResource",
      ]
      resources = [local.ecr_repository_arn]
    }
    ReadReportsBucket = {
      actions = [
        "s3:GetAccelerateConfiguration",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:ListBucket",
      ]
      resources = [local.reports_bucket_arn]
    }
    ReadKeys = {
      actions = [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
      ]
      resources = [local.kms_keys_arn]
    }
    ListAliases = {
      actions   = ["kms:ListAliases"] # not resource-scopable
      resources = ["*"]
    }
    ReadBudgets = {
      actions   = ["budgets:ViewBudget", "budgets:ListTagsForResource"]
      resources = [local.budgets_arn]
    }
  }
}

data "aws_iam_policy_document" "plan" {
  dynamic "statement" {
    for_each = local.read_statements
    content {
      sid       = statement.key
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

data "aws_iam_policy_document" "apply" {
  dynamic "statement" {
    for_each = local.read_statements
    content {
      sid       = statement.key
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }

  statement {
    sid       = "StateWrite"
    actions   = ["s3:PutObject"]
    resources = [local.state_object_arn]
  }

  # Role writes are only allowed when the role keeps the bootstrap's
  # permissions boundary, so apply cannot mint a role more powerful than CI.
  statement {
    sid = "ManageRolesUnderBoundary"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
    ]
    resources = [local.roles_arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arn]
    }
  }

  statement {
    sid = "ManageRoles"
    actions = [
      "iam:DeleteRole",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = [local.roles_arn]
  }

  statement {
    sid = "ManageGitHubOIDCProvider"
    actions = [
      "iam:AddClientIDToOpenIDConnectProvider",
      "iam:CreateOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:RemoveClientIDFromOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider",
      "iam:UntagOpenIDConnectProvider",
      "iam:UpdateOpenIDConnectProviderThumbprint",
    ]
    resources = [local.oidc_provider_arn]
  }

  statement {
    sid = "ManageRegistry"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteLifecyclePolicy",
      "ecr:DeleteRepository",
      "ecr:DeleteRepositoryPolicy",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:PutLifecyclePolicy",
      "ecr:SetRepositoryPolicy",
      "ecr:TagResource",
      "ecr:UntagResource",
    ]
    resources = [local.ecr_repository_arn]
  }

  statement {
    sid = "ManageReportsBucket"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketTagging",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = [local.reports_bucket_arn]
  }

  # CreateKey cannot be scoped to an ARN; require the project tag instead.
  statement {
    sid       = "CreateTaggedKeys"
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/project"
      values   = ["secpipe"]
    }
  }

  statement {
    sid = "ManageProjectKeys"
    actions = [
      "kms:CreateGrant",
      "kms:EnableKeyRotation",
      "kms:PutKeyPolicy",
      "kms:RetireGrant",
      "kms:ScheduleKeyDeletion",
      "kms:UntagResource",
      "kms:UpdateKeyDescription",
    ]
    resources = [local.kms_keys_arn]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/project"
      values   = ["secpipe"]
    }
  }

  statement {
    sid       = "ManageAliases"
    actions   = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
    resources = [local.kms_aliases_arn, local.kms_keys_arn]
  }

  statement {
    sid       = "ManageBudgets"
    actions   = ["budgets:ModifyBudget", "budgets:TagResource", "budgets:UntagResource"]
    resources = [local.budgets_arn]
  }
}

data "aws_iam_policy_document" "publish" {
  statement {
    sid       = "RegistryLogin"
    actions   = ["ecr:GetAuthorizationToken"] # not resource-scopable
    resources = ["*"]
  }

  statement {
    sid = "PushImages"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [local.ecr_repository_arn]
  }

  statement {
    sid       = "UploadReports"
    actions   = ["s3:PutObject"]
    resources = ["${local.reports_bucket_arn}/reports/*", "${local.reports_bucket_arn}/sbom/*"]
  }

  statement {
    sid       = "EncryptReports"
    actions   = ["kms:GenerateDataKey"]
    resources = [module.reports_bucket.kms_key_arn]
  }
}
