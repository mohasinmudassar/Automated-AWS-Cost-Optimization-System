import base64
import importlib
import json
import os
from datetime import datetime, timedelta

import boto3
import pytest
import responses
from responses import matchers

GITHUB_API = "https://api.github.com"
OWNER, REPO = "test-owner", "test-infra-repo"
TEST_TABLE = "stale-resources-test"

MATCH_TAGS = {"Name": "web-1", "owner": "alice@example.com"}


def test_ec2_cost_uses_known_rate():
    import pricing
    assert pricing.estimate_monthly_cost_usd("EC2", "t3.micro") == round(0.0104 * 730, 2)


def test_ec2_cost_unknown_instance_type_returns_none():
    import pricing
    assert pricing.estimate_monthly_cost_usd("EC2", "x9.enormous") is None


def test_nat_gw_cost():
    import pricing
    assert pricing.estimate_monthly_cost_usd("NAT_GW") == round(0.045 * 730, 2)


def test_lb_cost():
    import pricing
    assert pricing.estimate_monthly_cost_usd("LB") == round(0.0225 * 730, 2)


def test_unknown_resource_type_returns_none():
    import pricing
    assert pricing.estimate_monthly_cost_usd("SOMETHING_ELSE") is None


def _tree_response(paths):
    return {"tree": [{"path": p, "type": "blob", "sha": "x"} for p in paths]}


def _contents_response(text, sha="filesha123"):
    return {"content": base64.b64encode(text.encode()).decode(), "sha": sha}


WEB_TF_MATCHING_TAGS = """resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  tags = {
    Name  = "web-1"
    owner = "alice@example.com"
  }
}
"""

WEB_TF_DIFFERENT_TAGS = """resource "aws_instance" "web" {
  ami           = "ami-99999999"
  instance_type = "t3.small"

  tags = {
    Name  = "some-other-server"
    owner = "bob@example.com"
  }
}
"""

WEB_TF_NO_TAGS_BLOCK = """resource "aws_instance" "untagged" {
  ami           = "ami-11111111"
  instance_type = "t3.micro"
}
"""


def _mock_tree_and_file(path, content, ref="main", sha="filesha123"):
    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/git/trees/{ref}",
        json=_tree_response([path]),
        match=[matchers.query_param_matcher({"recursive": "1"})],
    )
    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/{path}",
        json=_contents_response(content, sha=sha),
        match=[matchers.query_param_matcher({"ref": ref})],
    )


@responses.activate
def test_locate_resource_finds_single_tag_match():
    import remediation

    _mock_tree_and_file("main.tf", WEB_TF_MATCHING_TAGS)

    path, start, end, lines, sha = remediation.locate_resource(
        OWNER, REPO, "main", MATCH_TAGS)

    assert path == "main.tf"
    assert lines[start].startswith('resource "aws_instance" "web"')
    assert lines[end] == "}"
    assert sha == "filesha123"


@responses.activate
def test_locate_resource_raises_when_tags_dont_match_any_block():
    import remediation

    _mock_tree_and_file("main.tf", WEB_TF_DIFFERENT_TAGS)

    with pytest.raises(remediation.RemediationError, match="No resource block"):
        remediation.locate_resource(OWNER, REPO, "main", MATCH_TAGS)


@responses.activate
def test_locate_resource_raises_when_no_resource_has_a_tags_block():
    import remediation

    _mock_tree_and_file("main.tf", WEB_TF_NO_TAGS_BLOCK)

    with pytest.raises(remediation.RemediationError, match="nothing to match against"):
        remediation.locate_resource(OWNER, REPO, "main", MATCH_TAGS)


@responses.activate
def test_locate_resource_raises_when_no_tags_on_finding():
    import remediation

    with pytest.raises(remediation.RemediationError, match="No tags on this finding"):
        remediation.locate_resource(OWNER, REPO, "main", {})


@responses.activate
def test_locate_resource_raises_when_ambiguous():
    import remediation

    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/git/trees/main",
        json=_tree_response(["a.tf", "b.tf"]),
        match=[matchers.query_param_matcher({"recursive": "1"})],
    )
    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/a.tf",
        json=_contents_response(WEB_TF_MATCHING_TAGS),
        match=[matchers.query_param_matcher({"ref": "main"})],
    )
    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/b.tf",
        json=_contents_response(
            WEB_TF_MATCHING_TAGS.replace('"web"', '"web_duplicate"')),
        match=[matchers.query_param_matcher({"ref": "main"})],
    )

    with pytest.raises(remediation.RemediationError, match="too ambiguous"):
        remediation.locate_resource(OWNER, REPO, "main", MATCH_TAGS)


def _mock_full_remediation_flow(file_content, base_sha="basesha1", file_sha="filesha123"):
    _mock_tree_and_file("main.tf", file_content, sha=file_sha)
    responses.add(
        responses.GET, f"{GITHUB_API}/repos/{OWNER}/{REPO}/git/ref/heads/main",
        json={"object": {"sha": base_sha}},
    )
    responses.add(
        responses.POST, f"{GITHUB_API}/repos/{OWNER}/{REPO}/git/refs",
        json={"ref": "refs/heads/x"}, status=201,
    )
    put_contents = responses.add(
        responses.PUT, f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/main.tf",
        json={"commit": {"sha": "newcommitsha"}}, status=200,
    )
    create_pr = responses.add(
        responses.POST, f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls",
        json={"html_url": f"https://github.com/{OWNER}/{REPO}/pull/1", "number": 1},
        status=201,
    )
    return put_contents, create_pr


@responses.activate
def test_remediate_remove_end_to_end():
    import remediation

    put_contents, create_pr = _mock_full_remediation_flow(WEB_TF_MATCHING_TAGS)

    finding = {
        "resource_id": "i-0abc123",
        "resource_type": "EC2",
        "region": "ap-southeast-1",
        "owner": "alice@example.com",
        "tags": MATCH_TAGS,
        "metrics": "CPU 2.1%, NetworkIn 1.2 MB/day, NetworkOut 0.8 MB/day",
        "threshold_crossed": "CPU < 10% and Network < 5 MB/day over 7 days",
        "action": "remove",
        "instance_type": "t3.micro",
    }

    result = remediation.remediate(finding)

    assert result == {
        "pr_url": f"https://github.com/{OWNER}/{REPO}/pull/1",
        "branch": "auto-remediation/ec2-i-0abc123",
    }

    put_body = put_contents.calls[0].request.body
    committed_content = base64.b64decode(
        json.loads(put_body)["content"]).decode()
    assert 'resource "aws_instance" "web"' not in committed_content

    pr_body = json.loads(create_pr.calls[0].request.body)["body"]
    assert "i-0abc123" in pr_body
    assert "CPU 2.1%" in pr_body
    assert "CPU < 10% and Network < 5 MB/day over 7 days" in pr_body
    assert "$7.59/month" in pr_body
    assert "stale=false" in pr_body
    assert "web-1" in pr_body


@responses.activate
def test_remediate_resize_changes_instance_type():
    import remediation

    put_contents, _ = _mock_full_remediation_flow(WEB_TF_MATCHING_TAGS)

    finding = {
        "resource_id": "i-0abc123",
        "resource_type": "EC2",
        "region": "ap-southeast-1",
        "owner": "alice@example.com",
        "tags": MATCH_TAGS,
        "metrics": "CPU 8%, well below m5.large's typical load",
        "threshold_crossed": "CPU < 10% sustained for 14 days",
        "action": "resize",
        "instance_type": "m5.large",
        "recommended_instance_type": "t3.small",
    }

    result = remediation.remediate(finding)
    assert result["branch"] == "auto-remediation/ec2-i-0abc123"

    put_body = json.loads(put_contents.calls[0].request.body)
    committed_content = base64.b64decode(put_body["content"]).decode()
    assert 'instance_type = "t3.small"' in committed_content
    assert 'instance_type = "t3.micro"' not in committed_content
    assert 'resource "aws_instance" "web"' in committed_content


@responses.activate
def test_remediate_raises_for_unknown_action():
    import remediation

    _mock_tree_and_file("main.tf", WEB_TF_MATCHING_TAGS)

    finding = {
        "resource_id": "i-0abc123",
        "resource_type": "EC2",
        "region": "ap-southeast-1",
        "owner": "alice@example.com",
        "tags": MATCH_TAGS,
        "metrics": "n/a",
        "threshold_crossed": "n/a",
        "action": "delete_immediately",
    }

    with pytest.raises(remediation.RemediationError, match="Unknown action"):
        remediation.remediate(finding)


def _put_finding(client, resource_id, resource_type, identification_time,
                  deletion_status="Marked", tags=None, extra=None):
    item = {
        'ResourceID': {'S': resource_id},
        'Type': {'S': resource_type},
        'Region': {'S': 'us-east-1'},
        'Creator': {'S': 'alice@example.com'},
        'Deletion_Status': {'S': deletion_status},
        'Identification_Time': {'S': identification_time},
        'Tags': {'M': {k: {'S': v} for k, v in (tags or {}).items()}},
        'Metrics': {'S': 'CPU 2%'},
        'ThresholdCrossed': {'S': 'CPU < 10%'},
    }
    if extra:
        item.update(extra)
    client.put_item(TableName=TEST_TABLE, Item=item)


def test_grace_period_elapsed_true_when_old_enough():
    import remediation
    old_time = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    assert remediation._grace_period_elapsed(
        {'Identification_Time': {'S': old_time}}) is True


def test_grace_period_elapsed_false_when_too_recent():
    import remediation
    recent_time = (datetime.utcnow() - timedelta(days=1)).strftime("%d-%m-%Y, %H:%M:%S")
    assert remediation._grace_period_elapsed(
        {'Identification_Time': {'S': recent_time}}) is False


def test_grace_period_elapsed_false_when_missing():
    import remediation
    assert remediation._grace_period_elapsed({}) is False


def test_pending_findings_filters_by_status_and_grace_period(aws):
    import remediation

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    recent = (datetime.utcnow() - timedelta(hours=1)).strftime("%d-%m-%Y, %H:%M:%S")

    _put_finding(client, "i-old-marked", "EC2", old)
    _put_finding(client, "i-recent-marked", "EC2", recent)
    _put_finding(client, "i-old-done", "EC2", old, deletion_status="PR_Opened")

    pending_ids = {item['ResourceID']['S'] for item in remediation._pending_findings()}
    assert pending_ids == {"i-old-marked"}


@responses.activate
def test_main_handler_pr_mode_opens_pr_and_marks_status(aws):
    import remediation

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, "i-0abc123", "EC2", old, tags=MATCH_TAGS)

    _mock_full_remediation_flow(WEB_TF_MATCHING_TAGS)

    result = remediation.main_handler({}, None)
    assert result == {"processed": 1}

    updated = client.get_item(
        TableName=TEST_TABLE,
        Key={'ResourceID': {'S': 'i-0abc123'}, 'Type': {'S': 'EC2'}},
    )['Item']
    assert updated['Deletion_Status']['S'] == 'PR_Opened'
    assert updated['RemediationResult']['S'] == f"https://github.com/{OWNER}/{REPO}/pull/1"


@responses.activate
def test_main_handler_leaves_unmatched_finding_marked_and_keeps_going(aws):
    import remediation

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, "i-no-match", "EC2", old, tags={"Name": "nothing-like-this"})

    _mock_tree_and_file("main.tf", WEB_TF_MATCHING_TAGS)

    result = remediation.main_handler({}, None)
    assert result == {"processed": 0}

    updated = client.get_item(
        TableName=TEST_TABLE,
        Key={'ResourceID': {'S': 'i-no-match'}, 'Type': {'S': 'EC2'}},
    )['Item']
    assert updated['Deletion_Status']['S'] == 'Marked'


def test_main_handler_skips_when_owner_opted_out_since_detection(aws):
    import remediation

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    instance_id = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        InstanceType="t3.micro", SubnetId=subnet,
        TagSpecifications=[{"ResourceType": "instance",
                             "Tags": [{"Key": "stale", "Value": "false"}]}],
    )["Instances"][0]["InstanceId"]

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, instance_id, "EC2", old, tags=MATCH_TAGS)

    result = remediation.main_handler({}, None)
    assert result == {"processed": 0}

    updated = client.get_item(
        TableName=TEST_TABLE,
        Key={'ResourceID': {'S': instance_id}, 'Type': {'S': 'EC2'}},
    )['Item']
    assert updated['Deletion_Status']['S'] == 'Excluded'


def test_main_handler_proceeds_when_current_tags_have_no_opt_out(aws):
    import remediation

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    instance_id = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        InstanceType="t3.micro", SubnetId=subnet,
    )["Instances"][0]["InstanceId"]

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, instance_id, "EC2", old, tags=MATCH_TAGS)

    assert remediation._owner_opted_out_since_detection(
        remediation._finding_from_dynamodb_item(
            client.get_item(
                TableName=TEST_TABLE,
                Key={'ResourceID': {'S': instance_id}, 'Type': {'S': 'EC2'}},
            )['Item']
        )
    ) is False


@pytest.fixture
def delete_mode():
    import remediation
    original_mode = os.environ.get("REMEDIATION_MODE")
    os.environ["REMEDIATION_MODE"] = "delete"
    importlib.reload(remediation.config)
    yield remediation
    if original_mode is None:
        os.environ.pop("REMEDIATION_MODE", None)
    else:
        os.environ["REMEDIATION_MODE"] = original_mode
    importlib.reload(remediation.config)


def test_main_handler_delete_mode_terminates_instance_and_marks_status(aws, delete_mode):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    instance_id = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        InstanceType="t3.micro", SubnetId=subnet,
    )["Instances"][0]["InstanceId"]

    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, instance_id, "EC2", old)

    result = delete_mode.main_handler({}, None)
    assert result == {"processed": 1}

    state = ec2.describe_instances(InstanceIds=[instance_id]
                                    )["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state in ("shutting-down", "terminated")

    updated = client.get_item(
        TableName=TEST_TABLE,
        Key={'ResourceID': {'S': instance_id}, 'Type': {'S': 'EC2'}},
    )['Item']
    assert updated['Deletion_Status']['S'] == 'Deleted'


def test_main_handler_delete_mode_lb_without_arn_raises_and_stays_marked(aws, delete_mode):
    client = boto3.client("dynamodb", region_name="us-east-1")
    old = (datetime.utcnow() - timedelta(days=8)).strftime("%d-%m-%Y, %H:%M:%S")
    _put_finding(client, "some-lb-id", "LB", old)

    result = delete_mode.main_handler({}, None)
    assert result == {"processed": 0}

    updated = client.get_item(
        TableName=TEST_TABLE,
        Key={'ResourceID': {'S': 'some-lb-id'}, 'Type': {'S': 'LB'}},
    )['Item']
    assert updated['Deletion_Status']['S'] == 'Marked'
