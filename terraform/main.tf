provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project = var.project_name
    }
  }
}

# ---------------------------------------------------------------------
# IAM — baseline role per function (CloudWatch Logs only).
# 3.8 adds each function's scoped permissions (DynamoDB, SES, SNS,
# CloudWatch, CloudTrail, the relevant Describe* calls) on top of this.
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

data "aws_iam_policy_document" "lambda_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role" "ec2_lambda" {
  name               = "${var.project_name}-ec2-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "ec2_lambda_logs" {
  name   = "${var.project_name}-ec2-lambda-logs"
  role   = aws_iam_role.ec2_lambda.id
  policy = data.aws_iam_policy_document.lambda_logs.json
}

resource "aws_iam_role" "lb_lambda" {
  name               = "${var.project_name}-lb-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "lb_lambda_logs" {
  name   = "${var.project_name}-lb-lambda-logs"
  role   = aws_iam_role.lb_lambda.id
  policy = data.aws_iam_policy_document.lambda_logs.json
}

resource "aws_iam_role" "nat_gw_lambda" {
  name               = "${var.project_name}-nat-gw-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "nat_gw_lambda_logs" {
  name   = "${var.project_name}-nat-gw-lambda-logs"
  role   = aws_iam_role.nat_gw_lambda.id
  policy = data.aws_iam_policy_document.lambda_logs.json
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
      SNS_TOPIC_ARN           = var.sns_topic_arn
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
      SNS_TOPIC_ARN              = var.sns_topic_arn
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
      SNS_TOPIC_ARN               = var.sns_topic_arn
      SES_SENDER                  = var.ses_sender
      NAT_GW_CONNECTION_THRESHOLD = var.nat_gw_connection_threshold
    }
  }
}
