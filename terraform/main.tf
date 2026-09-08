provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project = var.project_name
    }
  }
}

# ---------------------------------------------------------------------
# IAM — one role per function, each with a single inline policy scoped
# to exactly the API calls that function's code makes (verified against
# functions/{ec2,lb,nat_gw}/*.py, not copied from the old blanket
# policy). ec2:Describe*, elasticloadbalancing:Describe*,
# cloudwatch:GetMetricData, and cloudtrail:LookupEvents don't support
# resource-level scoping in IAM, so those stay on "*" — DynamoDB, SNS,
# and SES are scoped to the specific resources this config creates.
# No events:* or lambda:InvokeFunction/AddPermission/GetFunction here —
# those were only ever needed by the deletion-scheduling code 2.6
# removed.
# ---------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ec2_lambda" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid       = "DescribeEC2"
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeInstances", "ec2:DescribeTags"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }

  statement {
    sid       = "LookUpCreator"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid       = "RecordFindings"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.stale_resources.arn]
  }

  statement {
    sid       = "PublishSummary"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    sid       = "NotifyOwner"
    effect    = "Allow"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_ses_email_identity.sender.arn]
  }
}

resource "aws_iam_role" "ec2_lambda" {
  name               = "${var.project_name}-ec2-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "ec2_lambda" {
  name   = "${var.project_name}-ec2-lambda"
  role   = aws_iam_role.ec2_lambda.id
  policy = data.aws_iam_policy_document.ec2_lambda.json
}

data "aws_iam_policy_document" "lb_lambda" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid       = "DescribeRegions"
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions"]
    resources = ["*"]
  }

  statement {
    sid    = "DescribeLoadBalancers"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTags",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }

  statement {
    sid       = "LookUpCreator"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid       = "RecordFindings"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.stale_resources.arn]
  }

  statement {
    sid       = "PublishSummary"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    sid       = "NotifyOwner"
    effect    = "Allow"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_ses_email_identity.sender.arn]
  }
}

resource "aws_iam_role" "lb_lambda" {
  name               = "${var.project_name}-lb-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "lb_lambda" {
  name   = "${var.project_name}-lb-lambda"
  role   = aws_iam_role.lb_lambda.id
  policy = data.aws_iam_policy_document.lb_lambda.json
}

data "aws_iam_policy_document" "nat_gw_lambda" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid       = "DescribeEC2"
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeNatGateways", "ec2:DescribeTags"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }

  statement {
    sid       = "LookUpCreator"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid       = "RecordFindings"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.stale_resources.arn]
  }

  statement {
    sid       = "PublishSummary"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    sid       = "NotifyOwner"
    effect    = "Allow"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_ses_email_identity.sender.arn]
  }
}

resource "aws_iam_role" "nat_gw_lambda" {
  name               = "${var.project_name}-nat-gw-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "nat_gw_lambda" {
  name   = "${var.project_name}-nat-gw-lambda"
  role   = aws_iam_role.nat_gw_lambda.id
  policy = data.aws_iam_policy_document.nat_gw_lambda.json
}

# ---------------------------------------------------------------------
# Lambda deployment packages — one zip per handler directory.
# ---------------------------------------------------------------------
data "archive_file" "ec2" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/ec2"
  output_path = "${path.module}/build/ec2.zip"
}

data "archive_file" "lb" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/lb"
  output_path = "${path.module}/build/lb.zip"
}

data "archive_file" "nat_gw" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/nat_gw"
  output_path = "${path.module}/build/nat_gw.zip"
}

# ---------------------------------------------------------------------
# Lambda layer — layers/schema, published so all three functions can
# `from schema import config, import_schema`. Layer content has to live
# under python/ for the Lambda Python runtime to find it, and "schema"
# has to be an importable package, so each file is placed explicitly at
# python/schema/<file> rather than zipping layers/schema/ as-is (which
# would put the files at the zip root instead of nested under schema/).
# ---------------------------------------------------------------------
data "archive_file" "schema_layer" {
  type        = "zip"
  output_path = "${path.module}/build/schema-layer.zip"

  source {
    content  = file("${path.module}/../layers/schema/config.py")
    filename = "python/schema/config.py"
  }

  source {
    content  = file("${path.module}/../layers/schema/import_schema.py")
    filename = "python/schema/import_schema.py"
  }

  source {
    content  = file("${path.module}/../layers/schema/schema.json")
    filename = "python/schema/schema.json"
  }
}

resource "aws_lambda_layer_version" "schema" {
  layer_name          = "${var.project_name}-schema"
  filename            = data.archive_file.schema_layer.output_path
  source_code_hash    = data.archive_file.schema_layer.output_base64sha256
  compatible_runtimes = ["python3.13"]
}

# ---------------------------------------------------------------------
# Lambda functions. AWS_REGION is deliberately not set in environment
# variables — it's a reserved Lambda environment variable AWS populates
# automatically from the function's deployed region, and config.py
# already falls back to it.
# ---------------------------------------------------------------------
resource "aws_lambda_function" "ec2" {
  function_name    = "${var.project_name}-ec2-auditor"
  filename         = data.archive_file.ec2.output_path
  source_code_hash = data.archive_file.ec2.output_base64sha256
  handler          = "ec2.main_handler"
  runtime          = "python3.13"
  role             = aws_iam_role.ec2_lambda.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.schema.arn]

  environment {
    variables = {
      TABLE_NAME              = var.table_name
      SNS_TOPIC_ARN           = aws_sns_topic.notifications.arn
      SES_SENDER              = var.ses_sender
      CPU_THRESHOLD_PERCENT   = var.cpu_threshold_percent
      NETWORK_THRESHOLD_BYTES = var.network_threshold_bytes
    }
  }
}

resource "aws_lambda_function" "lb" {
  function_name    = "${var.project_name}-lb-auditor"
  filename         = data.archive_file.lb.output_path
  source_code_hash = data.archive_file.lb.output_base64sha256
  handler          = "lb.main_handler"
  runtime          = "python3.13"
  role             = aws_iam_role.lb_lambda.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.schema.arn]

  environment {
    variables = {
      TABLE_NAME                 = var.table_name
      SNS_TOPIC_ARN              = aws_sns_topic.notifications.arn
      SES_SENDER                 = var.ses_sender
      LB_REQUEST_COUNT_THRESHOLD = var.lb_request_count_threshold
    }
  }
}

resource "aws_lambda_function" "nat_gw" {
  function_name    = "${var.project_name}-nat-gw-auditor"
  filename         = data.archive_file.nat_gw.output_path
  source_code_hash = data.archive_file.nat_gw.output_base64sha256
  handler          = "nat_gw.main_handler"
  runtime          = "python3.13"
  role             = aws_iam_role.nat_gw_lambda.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.schema.arn]

  environment {
    variables = {
      TABLE_NAME                  = var.table_name
      SNS_TOPIC_ARN               = aws_sns_topic.notifications.arn
      SES_SENDER                  = var.ses_sender
      NAT_GW_CONNECTION_THRESHOLD = var.nat_gw_connection_threshold
    }
  }
}

# ---------------------------------------------------------------------
# DynamoDB — stale resource records. Hash/range key matches what all
# three handlers already write via put_item (ResourceID + Type), the
# same schema the Lambda-side create_table code used before 2.5 removed
# it. On-demand billing since scan volume is small and bursty, not a
# steady load worth provisioning capacity for.
# ---------------------------------------------------------------------
resource "aws_dynamodb_table" "stale_resources" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ResourceID"
  range_key    = "Type"

  point_in_time_recovery {
    enabled = true
  }

  attribute {
    name = "ResourceID"
    type = "S"
  }

  attribute {
    name = "Type"
    type = "S"
  }
}

# ---------------------------------------------------------------------
# SNS — ops/FinOps summary topic. Name matches the original hardcoded
# topic ("stale-resource-info") from before this was configurable,
# prefixed for uniqueness/tagging.
# ---------------------------------------------------------------------
resource "aws_sns_topic" "notifications" {
  name              = "${var.project_name}-stale-resource-info"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "ops_email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.ops_notification_email
}

# ---------------------------------------------------------------------
# SES — registers var.ses_sender as a verified identity. AWS emails
# that address a verification link; it won't actually be usable to send
# from until someone clicks it. Terraform can't do that step for you.
# ---------------------------------------------------------------------
resource "aws_ses_email_identity" "sender" {
  email = var.ses_sender
}

# ---------------------------------------------------------------------
# EventBridge — scan schedule only. There is no deletion schedule: 2.6
# removed the EC2 handler's deletion-scheduling code entirely, and
# remediation becomes PR-based in Phase 5, not EventBridge-triggered.
# One rule, three targets — each target's static `input` matches
# exactly what that handler's main_handler(event, context) reads.
# ---------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "scan_schedule" {
  name                = "${var.project_name}-scan-schedule"
  schedule_expression = var.scan_schedule_expression
}

resource "aws_cloudwatch_event_target" "ec2_scan" {
  rule = aws_cloudwatch_event_rule.scan_schedule.name
  arn  = aws_lambda_function.ec2.arn
  input = jsonencode({
    major      = "EC2"
    minor      = "instance"
    time_frame = var.time_frame_days
  })
}

resource "aws_lambda_permission" "ec2_scan" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}

resource "aws_cloudwatch_event_target" "lb_scan" {
  rule = aws_cloudwatch_event_rule.scan_schedule.name
  arn  = aws_lambda_function.lb.arn
  input = jsonencode({
    major = "LB"
  })
}

resource "aws_lambda_permission" "lb_scan" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lb.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}

resource "aws_cloudwatch_event_target" "nat_gw_scan" {
  rule = aws_cloudwatch_event_rule.scan_schedule.name
  arn  = aws_lambda_function.nat_gw.arn
  input = jsonencode({
    major = "GW"
    minor = "nat_gw"
  })
}

resource "aws_lambda_permission" "nat_gw_scan" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.nat_gw.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}
