import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Mirrors how the Lambda layer makes `schema` importable, and how each
# function's zip puts its own module at the root — so `from schema import
# config, import_schema` and `import ec2` / `lb` / `nat_gw` work exactly
# the way they do in Lambda, without duplicating any source under tests/.
for path in (
    REPO_ROOT / "layers",
    REPO_ROOT / "functions" / "ec2",
    REPO_ROOT / "functions" / "lb",
    REPO_ROOT / "functions" / "nat_gw",
):
    sys.path.insert(0, str(path))

# config.py reads these once, at first import, and every handler module
# imports it at module scope — so these have to be set before any test
# file (or this conftest) imports ec2/lb/nat_gw/config for the first
# time, and they have to stay constant for the rest of the session.
# TEST_ACCOUNT_ID and the SNS topic name below are chosen so the real
# topic moto creates in the `aws` fixture gets exactly this ARN.
TEST_ACCOUNT_ID = "123456789012"
TEST_REGION = "us-east-1"
SNS_TOPIC_NAME = "stale-resource-info"

# Dummy, obviously-fake credentials — not for moto's benefit (it doesn't
# check them), but so that if a call ever escapes the mock and reaches
# real AWS, it fails on bad credentials instead of silently running
# against whatever account happens to be configured on the machine.
os.environ["AWS_REGION"] = TEST_REGION
os.environ["AWS_DEFAULT_REGION"] = TEST_REGION
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["TABLE_NAME"] = "stale-resources-test"
os.environ["SNS_TOPIC_ARN"] = f"arn:aws:sns:{TEST_REGION}:{TEST_ACCOUNT_ID}:{SNS_TOPIC_NAME}"
os.environ["SES_SENDER"] = "ops@example.com"

import boto3  # noqa: E402  (after sys.path/env setup, before use below)
import pytest  # noqa: E402
from moto import mock_aws  # noqa: E402


@pytest.fixture
def aws():
    """Mocked AWS with the shared table/topic/identity every handler
    needs already in place. Each test gets a fresh account — moto resets
    all state when the context manager exits."""
    with mock_aws():
        dynamodb = boto3.client("dynamodb", region_name=TEST_REGION)
        dynamodb.create_table(
            TableName=os.environ["TABLE_NAME"],
            KeySchema=[
                {"AttributeName": "ResourceID", "KeyType": "HASH"},
                {"AttributeName": "Type", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "ResourceID", "AttributeType": "S"},
                {"AttributeName": "Type", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        sns = boto3.client("sns", region_name=TEST_REGION)
        sns.create_topic(Name=SNS_TOPIC_NAME)

        ses = boto3.client("ses", region_name=TEST_REGION)
        ses.verify_email_identity(EmailAddress=os.environ["SES_SENDER"])

        yield


@pytest.fixture
def dynamodb_items(aws):
    """Every item currently in the stale-resources table, as a list of
    plain dicts (unwrapped from DynamoDB's {'S': ...} type envelopes)."""
    def _read():
        client = boto3.client("dynamodb", region_name=TEST_REGION)
        scan = client.scan(TableName=os.environ["TABLE_NAME"])
        return [
            {k: v["S"] for k, v in item.items()}
            for item in scan["Items"]
        ]
    return _read


class Backdate:
    """Backdates a resource's creation timestamp via moto's internal
    model state, so it looks old enough to reach a handler's
    metrics-evaluation branch (age >= TIME_FRAME).

    Deliberately NOT done by patching datetime.now() forward: that also
    shifts the handler's CloudWatch query window into the future, and
    moto's get_metric_data returns nothing for a future-windowed query
    regardless of when the underlying data point was actually inserted
    (verified directly — a metric timestamped to match the faked future
    "now" still came back empty). Backdating only the resource leaves
    real time untouched, so metric data timestamped at the real current
    time is correctly inside the query window.
    """

    @staticmethod
    def ec2_instance(instance_id, days):
        from moto.ec2 import ec2_backends
        old_time = datetime.now(timezone.utc) - timedelta(days=days)
        backend = ec2_backends[TEST_ACCOUNT_ID][TEST_REGION]
        backend.get_instance(instance_id).launch_time = \
            old_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    @staticmethod
    def load_balancer(lb_arn, days):
        from moto.elbv2 import elbv2_backends
        old_time = datetime.now(timezone.utc) - timedelta(days=days)
        backend = elbv2_backends[TEST_ACCOUNT_ID][TEST_REGION]
        backend.load_balancers[lb_arn].created_time = old_time

    @staticmethod
    def nat_gateway(nat_gateway_id, days):
        from moto.ec2 import ec2_backends
        old_time = datetime.now(timezone.utc) - timedelta(days=days)
        backend = ec2_backends[TEST_ACCOUNT_ID][TEST_REGION]
        backend.nat_gateways[nat_gateway_id]._created_at = old_time


@pytest.fixture
def backdate(aws):
    return Backdate()
