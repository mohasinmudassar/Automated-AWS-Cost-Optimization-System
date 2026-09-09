provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project = var.project_name
    }
  }
}

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

data "aws_iam_policy_document" "remediation_lambda" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid       = "ReadAndMarkFindings"
    effect    = "Allow"
    actions   = ["dynamodb:Scan", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.stale_resources.arn]
  }

  statement {
    sid       = "RecheckCurrentTagsBeforeActing"
    effect    = "Allow"
    actions   = ["ec2:DescribeTags", "elasticloadbalancing:DescribeTags"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = var.remediation_mode == "delete" ? [1] : []
    content {
      sid    = "DeleteResources"
      effect = "Allow"
      actions = [
        "ec2:TerminateInstances",
        "ec2:DeleteNatGateway",
        "elasticloadbalancing:DeleteLoadBalancer",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role" "remediation_lambda" {
  name               = "${var.project_name}-remediation-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "remediation_lambda" {
  name   = "${var.project_name}-remediation-lambda"
  role   = aws_iam_role.remediation_lambda.id
  policy = data.aws_iam_policy_document.remediation_lambda.json
}

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

resource "terraform_data" "remediation_build" {
  triggers_replace = [
    filesha256("${path.module}/../functions/remediation/requirements.txt"),
    filesha256("${path.module}/../functions/remediation/remediation.py"),
    filesha256("${path.module}/../functions/remediation/config.py"),
    filesha256("${path.module}/../functions/remediation/pricing.py"),
  ]

  provisioner "local-exec" {
    command = <<-EOT
      set -e
      rm -rf ${path.module}/build/remediation_pkg
      mkdir -p ${path.module}/build/remediation_pkg
      pip3 install --quiet -r ${path.module}/../functions/remediation/requirements.txt -t ${path.module}/build/remediation_pkg
      cp ${path.module}/../functions/remediation/*.py ${path.module}/build/remediation_pkg/
    EOT
  }
}

data "archive_file" "remediation" {
  type        = "zip"
  source_dir  = "${path.module}/build/remediation_pkg"
  output_path = "${path.module}/build/remediation.zip"

  depends_on = [terraform_data.remediation_build]
}

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

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.project_name}-remediation"
  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256
  handler          = "remediation.main_handler"
  runtime          = "python3.13"
  role             = aws_iam_role.remediation_lambda.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = merge(
      {
        TABLE_NAME             = var.table_name
        DELETION_DELAY_MINUTES = var.deletion_delay_minutes
        REMEDIATION_MODE       = var.remediation_mode
      },
      var.remediation_mode == "pr" ? {
        GITHUB_TOKEN  = var.github_token
        TARGET_REPO   = var.target_repo
        BRANCH_PREFIX = var.branch_prefix
        BASE_BRANCH   = var.base_branch
      } : {}
    )
  }
}

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

resource "aws_sns_topic" "notifications" {
  name              = "${var.project_name}-stale-resource-info"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "ops_email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.ops_notification_email
}

resource "aws_ses_email_identity" "sender" {
  email = var.ses_sender
}

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

resource "aws_cloudwatch_event_target" "remediation_scan" {
  rule = aws_cloudwatch_event_rule.scan_schedule.name
  arn  = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "remediation_scan" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}
