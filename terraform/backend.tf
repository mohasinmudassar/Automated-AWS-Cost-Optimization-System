# Backend values (bucket, key, region) are supplied at `terraform init`
# time via -backend-config, since backend blocks can't reference
# variables. Copy backend.hcl.example to backend.hcl (gitignored) and
# fill in your own values, then run:
#   terraform init -backend-config=backend.hcl
#
# The S3 bucket itself must exist ahead of time, with versioning and
# default encryption already enabled on it — Terraform's S3 backend
# stores state in an existing bucket, it doesn't provision one (this
# config can't create the very bucket it needs as its own backend).
terraform {
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
