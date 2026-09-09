variable "project_name" {
  description = "Short name used to prefix and tag every resource this config creates."
  type        = string
}

variable "aws_region" {
  description = "AWS region every resource is deployed into."
  type        = string
  default     = "ap-southeast-1"
}

variable "lambda_timeout" {
  description = "Timeout, in seconds, for the auditor Lambda functions."
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Memory, in MB, for the auditor Lambda functions."
  type        = number
  default     = 256
}

variable "table_name" {
  description = "DynamoDB table stale resources are recorded in."
  type        = string
}

variable "ses_sender" {
  description = "Verified SES sender address owner notifications are sent from."
  type        = string
}

variable "ops_notification_email" {
  description = "Ops/FinOps email address subscribed to the SNS summary topic."
  type        = string
}

variable "cpu_threshold_percent" {
  description = "EC2: CPU utilization percent below which an instance is considered idle."
  type        = number
  default     = 10
}

variable "network_threshold_bytes" {
  description = "EC2: NetworkIn/NetworkOut bytes below which an instance is considered idle."
  type        = number
  default     = 5 * 1024 * 1024
}

variable "lb_request_count_threshold" {
  description = "LB: request count below which a load balancer is considered idle."
  type        = number
  default     = 1000
}

variable "nat_gw_connection_threshold" {
  description = "NAT Gateway: connection attempt count below which a gateway is considered idle."
  type        = number
  default     = 7
}

variable "deletion_delay_minutes" {
  description = "Grace period, in minutes, before a flagged resource is eligible for remediation (~7 days). Read by the remediation Lambda to decide which findings are due."
  type        = number
  default     = 10050
}

variable "scan_schedule_expression" {
  description = "EventBridge schedule expression the three scans (and remediation) run on."
  type        = string
  default     = "rate(1 day)"
}

variable "time_frame_days" {
  description = "Lookback window, in days, used to decide whether a resource is idle. Passed to the EC2 scan via its event payload; lb.py and nat_gw.py hardcode the same default (7) themselves."
  type        = number
  default     = 7
}

variable "remediation_mode" {
  description = "\"pr\" (default) opens a pull request against target_repo proposing removal/resize. \"delete\" calls AWS directly to terminate/delete the resource instead — a separate, explicit opt-in; Terraform only grants the remediation Lambda's role delete permissions when this is actually set to \"delete\"."
  type        = string
  default     = "pr"
  validation {
    condition     = contains(["pr", "delete"], var.remediation_mode)
    error_message = "remediation_mode must be \"pr\" or \"delete\"."
  }
}

variable "github_token" {
  description = "GitHub token with write access on target_repo. Only used (and only required) when remediation_mode = \"pr\". Never given a real default — set via terraform.tfvars (gitignored) or your CI secret store, never committed."
  type        = string
  default     = null
  sensitive   = true
}

variable "target_repo" {
  description = "\"owner/repo\" of the Terraform repo remediation PRs are opened against. Only required when remediation_mode = \"pr\"."
  type        = string
  default     = null
}

variable "branch_prefix" {
  description = "Prefix for the branch remediation creates for each PR."
  type        = string
  default     = "auto-remediation"
}

variable "base_branch" {
  description = "Branch in target_repo that remediation branches from and opens PRs against."
  type        = string
  default     = "main"
}
