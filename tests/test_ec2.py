from datetime import datetime, timezone

import boto3
import pytest


@pytest.fixture
def subnet(aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    return ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]


def _create_instance(subnet, tags):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    reservation = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        InstanceType="t3.micro", SubnetId=subnet,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
    )
    return reservation["Instances"][0]["InstanceId"]


def _put_metric(instance_id, metric_name, value, unit):
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(Namespace="AWS/EC2", MetricData=[{
        "MetricName": metric_name,
        "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
        "Timestamp": datetime.now(timezone.utc),
        "Value": value,
        "Unit": unit,
    }])


def test_idle_instance_is_flagged(subnet, backdate, dynamodb_items):
    import ec2 as ec2_module

    instance_id = _create_instance(subnet, [
        {"Key": "creator", "Value": "alice@example.com"},
        {"Key": "Name", "Value": "web-1"},
    ])
    backdate.ec2_instance(instance_id, days=30)
    _put_metric(instance_id, "CPUUtilization", 2.0, "Percent")
    _put_metric(instance_id, "NetworkIn", 1024, "Bytes")
    _put_metric(instance_id, "NetworkOut", 1024, "Bytes")

    ec2_module.main_handler(
        {"major": "EC2", "minor": "instance", "time_frame": 7}, None)

    items = dynamodb_items()
    assert len(items) == 1
    assert items[0]["Tags"] == {"creator": "alice@example.com", "Name": "web-1"}
    assert "CPUUtilization 2.0%" in items[0]["Metrics"]
    assert "CPU <" in items[0]["ThresholdCrossed"]
    assert items[0]["InstanceType"] == "t3.micro"
    assert items[0]["ResourceID"] == instance_id
    assert items[0]["Creator"] == "alice@example.com"


def test_busy_instance_is_not_flagged(subnet, backdate, dynamodb_items):
    import ec2 as ec2_module

    instance_id = _create_instance(
        subnet, [{"Key": "creator", "Value": "bob@example.com"}])
    backdate.ec2_instance(instance_id, days=30)
    _put_metric(instance_id, "CPUUtilization", 75.0, "Percent")
    _put_metric(instance_id, "NetworkIn", 50 * 1024 * 1024, "Bytes")
    _put_metric(instance_id, "NetworkOut", 50 * 1024 * 1024, "Bytes")

    ec2_module.main_handler(
        {"major": "EC2", "minor": "instance", "time_frame": 7}, None)

    assert dynamodb_items() == []


def test_stale_false_tagged_instance_is_excluded(subnet, backdate, dynamodb_items):
    import ec2 as ec2_module

    instance_id = _create_instance(subnet, [
        {"Key": "creator", "Value": "carol@example.com"},
        {"Key": "stale", "Value": "false"},
    ])
    backdate.ec2_instance(instance_id, days=30)

    ec2_module.main_handler(
        {"major": "EC2", "minor": "instance", "time_frame": 7}, None)

    assert dynamodb_items() == []
