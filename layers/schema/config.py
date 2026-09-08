import os


class ConfigError(Exception):
    """Raised when a required environment variable is missing or invalid."""


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(
            f"Environment variable {name} must be an integer, got: {raw!r}")


# Region every boto3 client in the handlers is created with.
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

# DynamoDB table stale resources are recorded in.
TABLE_NAME = _require("TABLE_NAME")

# Notification targets.
SNS_TOPIC_ARN = _require("SNS_TOPIC_ARN")
SES_SENDER = _require("SES_SENDER")

# Idle-detection thresholds.
CPU_THRESHOLD_PERCENT = _get_int("CPU_THRESHOLD_PERCENT", 10)
NETWORK_THRESHOLD_BYTES = _get_int("NETWORK_THRESHOLD_BYTES", 5 * 1024 * 1024)
LB_REQUEST_COUNT_THRESHOLD = _get_int("LB_REQUEST_COUNT_THRESHOLD", 1000)
NAT_GW_CONNECTION_THRESHOLD = _get_int("NAT_GW_CONNECTION_THRESHOLD", 7)

# Delay before a flagged resource becomes eligible for deletion (~7 days).
DELETION_DELAY_MINUTES = _get_int("DELETION_DELAY_MINUTES", 10050)
