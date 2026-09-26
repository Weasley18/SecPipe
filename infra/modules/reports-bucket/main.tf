# Private, encrypted, versioned bucket for gate reports and SBOMs: all public
# access blocked, ACLs disabled, SSE-KMS by default, TLS-only access and a
# 90-day lifecycle so evidence does not pile up forever.

data "aws_caller_identity" "current" {}

locals {
  tags = merge(var.tags, { owner = var.owner })
}

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

resource "aws_kms_key" "reports" {
  description             = "SSE-KMS for ${var.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "reports" {
  name          = "alias/secpipe-reports"
  target_key_id = aws_kms_key.reports.key_id
}

# justification: server access logs need a second paid bucket; CloudTrail data events are the upgrade path.
#trivy:ignore:AWS-0089
resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_18:Server access logging needs a second log bucket that costs money for a demo; CloudTrail data events are the upgrade path (docs/adr/0006).
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles storage cost; reports are reproducible from CI artifacts.
  #checkov:skip=CKV2_AWS_62:No consumer for S3 event notifications in the demo account.
  bucket        = var.bucket_name
  force_destroy = false
  tags          = local.tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs entirely
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.reports.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "expire-reports"
    status = "Enabled"
    filter {}

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = length(var.writer_role_arns) > 0 ? [1] : []
    content {
      sid       = "CIWritesReports"
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.this.arn}/reports/*", "${aws_s3_bucket.this.arn}/sbom/*"]
      principals {
        type        = "AWS"
        identifiers = var.writer_role_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.this]
}
