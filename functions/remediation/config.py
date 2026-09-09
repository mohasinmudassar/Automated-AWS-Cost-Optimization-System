import os


class ConfigError(Exception):
    pass


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


AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
TABLE_NAME = _require("TABLE_NAME")

DELETION_DELAY_MINUTES = _get_int("DELETION_DELAY_MINUTES", 10050)

REMEDIATION_MODE = os.environ.get("REMEDIATION_MODE", "pr")
if REMEDIATION_MODE not in ("pr", "delete"):
    raise ConfigError(
        f"REMEDIATION_MODE must be 'pr' or 'delete', got: {REMEDIATION_MODE!r}")

if REMEDIATION_MODE == "pr":
    GITHUB_TOKEN = _require("GITHUB_TOKEN")
    TARGET_REPO = _require("TARGET_REPO")
    BRANCH_PREFIX = os.environ.get("BRANCH_PREFIX", "auto-remediation")
    BASE_BRANCH = os.environ.get("BASE_BRANCH", "main")
else:
    GITHUB_TOKEN = None
    TARGET_REPO = None
    BRANCH_PREFIX = None
    BASE_BRANCH = None
