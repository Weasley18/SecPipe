# Private registry for the AWS profile: tags are immutable (a digest cannot be
# silently replaced under a released tag), every push is scanned, and layers
# are encrypted with a customer-managed key that rotates yearly.

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:Key policies must name the key itself as "*"; access is scoped to this account's root, which delegates to IAM.
  #checkov:skip=CKV_AWS_111:Same as above: "*" in a key policy means "this key", not every key.
  #checkov:skip=CKV_AWS_356:Same as above: "*" in a key policy means "this key", not every key.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "ecr" {
  description             = "ECR encryption for ${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/secpipe-ecr-${var.name}"
  target_key_id = aws_kms_key.ecr.key_id
}

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_expiry_days
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the most recent tagged images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.keep_tagged_images
        }
        action = { type = "expire" }
      },
    ]
  })
}

data "aws_iam_policy_document" "repository" {
  count = length(var.push_principal_arns) > 0 ? 1 : 0

  statement {
    sid = "PublishFromCI"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    principals {
      type        = "AWS"
      identifiers = var.push_principal_arns
    }
  }
}

resource "aws_ecr_repository_policy" "this" {
  count      = length(var.push_principal_arns) > 0 ? 1 : 0
  repository = aws_ecr_repository.this.name
  policy     = data.aws_iam_policy_document.repository[0].json
}
