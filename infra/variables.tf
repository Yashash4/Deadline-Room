# Account-specific inputs. Every value here is supplied by the deployer (tfvars or
# TF_VAR_); none is fabricated. Cloud ids (account number, key arn, cluster name)
# are produced by apply, never written in.

variable "region" {
  description = "AWS region for the Deadline Room footprint."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Name prefix applied to every resource, so one account can host more than one environment."
  type        = string
  default     = "deadline-room"
}

variable "environment" {
  description = "Environment label (e.g. prod, staging) folded into tags."
  type        = string
  default     = "prod"
}

variable "band_api_key" {
  description = "The Band platform API key. Supplied at apply time (TF_VAR_band_api_key); never committed."
  type        = string
  sensitive   = true
  default     = ""
}

variable "featherless_api_key" {
  description = "The Featherless model-gateway API key. Supplied at apply time; never committed."
  type        = string
  sensitive   = true
  default     = ""
}

variable "tsa_url" {
  description = "The RFC 3161 Time-Stamping Authority endpoint the Warden timestamps signatures against (E2.4). A real TSA (DigiCert, freeTSA) in production; empty falls back to the offline demo TSA."
  type        = string
  default     = ""
}

variable "corpus_retention_days" {
  description = "How long sealed run-log artifacts are retained in object storage."
  type        = number
  default     = 3650
}
