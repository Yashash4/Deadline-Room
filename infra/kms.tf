# The signing-key custody (E2.5): an asymmetric KMS key the Warden signs through,
# so the private key never leaves the KMS and no private seed lives in the repo.
# The warden/custody.py KmsProvider points at this key's arn (an apply output); its
# sign call is AWS kms.sign with the EDDSA algorithm, and the verifier is unchanged.
resource "aws_kms_key" "warden_signing" {
  description              = "${var.name_prefix} Warden run-log signing key (asymmetric, non-exportable)."
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  enable_key_rotation      = false

  tags = {
    Name        = "${var.name_prefix}-warden-signing"
    Environment = var.environment
    Component   = "custody"
  }
}

resource "aws_kms_alias" "warden_signing" {
  name          = "alias/${var.name_prefix}-warden-signing"
  target_key_id = aws_kms_key.warden_signing.key_id
}

# A distinct key for the RFC 3161 TSA role (E2.4): signer and time authority are
# separate roles held by separate keys, both routed through the one custody seam.
resource "aws_kms_key" "tsa_signing" {
  description              = "${var.name_prefix} RFC 3161 TSA timestamp-token signing key."
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30

  tags = {
    Name        = "${var.name_prefix}-tsa-signing"
    Environment = var.environment
    Component   = "timestamp"
  }
}

resource "aws_kms_alias" "tsa_signing" {
  name          = "alias/${var.name_prefix}-tsa-signing"
  target_key_id = aws_kms_key.tsa_signing.key_id
}
