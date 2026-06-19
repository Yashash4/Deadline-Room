# Apply-time outputs the deployer feeds into the runtime (warden/custody.py and the
# Kubernetes Secret). These are produced by apply, never fabricated here.

output "warden_kms_key_arn" {
  description = "Arn of the asymmetric KMS key the Warden signs run logs through (warden/custody.py KmsProvider key_id)."
  value       = aws_kms_key.warden_signing.arn
}

output "tsa_kms_key_arn" {
  description = "Arn of the KMS key the RFC 3161 TSA signs timestamp tokens with."
  value       = aws_kms_key.tsa_signing.arn
}

output "runtime_secret_arn" {
  description = "Arn of the Secrets Manager secret projected into the deadline-room-secrets Kubernetes Secret."
  value       = aws_secretsmanager_secret.runtime.arn
}

output "corpus_bucket" {
  description = "Name of the versioned, encrypted bucket holding the sealed-artifact corpus."
  value       = aws_s3_bucket.corpus.bucket
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster hosting the standing governance service."
  value       = aws_ecs_cluster.main.name
}
