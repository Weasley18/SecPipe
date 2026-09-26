# Fixtures for policy/checkov: every resource named pass_* must pass and every
# fail_* must fail. Run with scripts/ci/checkov-policy-test.sh.

resource "aws_s3_bucket" "pass_owner" {
  bucket = "pass-owner"
  tags   = { owner = "team-a" }
}

resource "aws_s3_bucket" "pass_owner_merged" {
  bucket = "pass-owner-merged"
  tags   = merge({ project = "secpipe" }, { owner = "team-a" })
}

resource "aws_s3_bucket" "fail_no_tags" {
  bucket = "fail-no-tags"
}

resource "aws_s3_bucket" "fail_other_tags" {
  bucket = "fail-other-tags"
  tags   = { project = "secpipe" }
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "pass_exact" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:Weasley18/SecPipe:ref:refs/heads/main",
        "repo:Weasley18/SecPipe:environment:aws-demo",
        "repo:Weasley18/SecPipe:pull_request",
      ]
    }
  }
}

data "aws_iam_policy_document" "fail_owner_wildcard" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Weasley18/*"]
    }
  }
}

data "aws_iam_policy_document" "fail_branch_wildcard" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Weasley18/SecPipe:*"]
    }
  }
}

data "aws_iam_policy_document" "fail_audience_only" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

locals {
  github_owner = "Weasley18"
}

data "aws_iam_policy_document" "fail_interpolated_wildcard" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_owner}/*"]
    }
  }
}
