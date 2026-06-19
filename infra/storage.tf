# Durable storage for the sealed-artifact corpus the persistent service reads and
# the Warden audits. The sealed run-log JSONL files plus their signature, in-toto,
# and timestamp sidecars are the system of record, so the bucket is versioned and
# tamper-resistant: object lock and versioning mean a sealed artifact cannot be
# silently overwritten, which complements the in-band chain/signature tamper
# evidence the Warden already provides.
resource "aws_s3_bucket" "corpus" {
  bucket = "${var.name_prefix}-corpus"

  tags = {
    Name        = "${var.name_prefix}-corpus"
    Environment = var.environment
    Component   = "corpus"
  }
}

resource "aws_s3_bucket_versioning" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.warden_signing.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "corpus" {
  bucket                  = aws_s3_bucket.corpus.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    id     = "retain-sealed-artifacts"
    status = "Enabled"
    filter {}
    expiration {
      days = var.corpus_retention_days
    }
  }
}
