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

# --- Values consumed by layers/schema/config.py (functions/*) ---

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

# Intentionally unused until Phase 5 wires PR-based remediation through
# it; kept here now rather than deleted-and-recreated later.
# tflint-ignore: terraform_unused_declarations
variable "deletion_delay_minutes" {
  description = "Grace period, in minutes, before a flagged resource is eligible for remediation (~7 days). Not yet wired to any function — reserved for Phase 5."
  type        = number
  default     = 10050
}

# --- Scan scheduling ---

variable "scan_schedule_expression" {
  description = "EventBridge schedule expression the three scans run on."
  type        = string
  default     = "rate(1 day)"
}

variable "time_frame_days" {
  description = "Lookback window, in days, used to decide whether a resource is idle. Passed to the EC2 scan via its event payload; lb.py and nat_gw.py hardcode the same default (7) themselves."
  type        = number
  default     = 7
}
