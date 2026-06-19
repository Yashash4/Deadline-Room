# Deadline Room: cloud footprint (Terraform)

Declarative infrastructure for the production Deadline Room: the signing-key
custody (E2.5), secret storage, the sealed-artifact corpus store, the RFC 3161 TSA
endpoint reference (E2.4), and the persistent governance service (E6.7).

Every account-specific value (region, account number, key arn, cluster name, image
reference, IAM role arn) is an input the deployer supplies or an output `apply`
produces. Nothing here fabricates a cloud id.

## Files

- `versions.tf` provider and version constraints.
- `variables.tf` deployer inputs (region, name prefix, the Band and model API keys,
  the TSA url, retention).
- `kms.tf` the asymmetric KMS keys the Warden and the TSA sign through, so no
  private seed lives in the repo (`warden/custody.py` KmsProvider).
- `secrets.tf` the Secrets Manager secret projected into the `deadline-room-secrets`
  Kubernetes Secret the `deploy/` manifests reference.
- `storage.tf` the versioned, KMS-encrypted bucket holding the sealed corpus.
- `service.tf` the ECS Fargate footprint for the standing governance service (the
  Helm chart in `deploy/` is the Kubernetes equivalent).
- `outputs.tf` the apply-time arns and names the runtime consumes.

## Apply

```
cd infra
terraform init
terraform plan  -var="region=us-east-1" -var="band_api_key=..." -var="featherless_api_key=..."
terraform apply -var="region=us-east-1" -var="band_api_key=..." -var="featherless_api_key=..."
```

The signing key is non-exportable: the private key never leaves the KMS, and the
Warden's `KmsProvider.sign` is an AWS `kms.sign` EDDSA call. The verifier and the
sealed signatures are unchanged; only WHERE the key lives changes.
