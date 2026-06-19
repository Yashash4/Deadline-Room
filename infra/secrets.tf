# Secret storage for the runtime credentials the agents need: the Band and model
# API keys, the KMS key arn the custody provider signs through, and the TSA
# endpoint. The values are supplied at apply time (sensitive variables) and are
# never written into the repo. A deployment's external-secrets / CSI driver
# projects this Secrets Manager secret into the Kubernetes Secret named
# deadline-room-secrets that the manifests in deploy/ reference by name.
resource "aws_secretsmanager_secret" "runtime" {
  name        = "${var.name_prefix}/runtime"
  description = "Runtime credentials for the Deadline Room agents (Band + model keys, KMS key arn, TSA url)."

  tags = {
    Name        = "${var.name_prefix}-runtime"
    Environment = var.environment
    Component   = "secrets"
  }
}

resource "aws_secretsmanager_secret_version" "runtime" {
  secret_id = aws_secretsmanager_secret.runtime.id
  secret_string = jsonencode({
    BAND_API_KEY                = var.band_api_key
    FEATHERLESS_API_KEY         = var.featherless_api_key
    DEADLINE_ROOM_KMS_KEY_ARN   = aws_kms_key.warden_signing.arn
    DEADLINE_ROOM_TSA_KEY_ARN   = aws_kms_key.tsa_signing.arn
    DEADLINE_ROOM_TSA_URL       = var.tsa_url
  })
}
