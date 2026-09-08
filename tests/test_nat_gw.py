from datetime import datetime, timezone

import boto3
import pytest


@pytest.fixture
def subnet(aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
    return ec2.create_subnet(VpcId=vpc, CidrBlock="10.2.1.0/24")["Subnet"]["SubnetId"]


def _create_nat_gateway(subnet, tags):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat_gateway_id = ec2.create_nat_gateway(
        SubnetId=subnet, AllocationId=eip)["NatGateway"]["NatGatewayId"]
    ec2.create_tags(Resources=[nat_gateway_id], Tags=tags)
    return nat_gateway_id


def _put_connection_count(nat_gateway_id, value):
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(Namespace="AWS/NATGateway", MetricData=[{
        "MetricName": "ActiveConnectionCount",
        "Dimensions": [{"Name": "NatGatewayId", "Value": nat_gateway_id}],
        "Timestamp": datetime.now(timezone.utc),
        "Value": value,
        "Unit": "Count",
    }])


def test_idle_nat_gateway_is_flagged(subnet, backdate, dynamodb_items):
    import nat_gw as nat_gw_module

    nat_gateway_id = _create_nat_gateway(
        subnet, [{"Key": "creator", "Value": "carol@example.com"}])
    backdate.nat_gateway(nat_gateway_id, days=30)
    _put_connection_count(nat_gateway_id, 1)

    nat_gw_module.main_handler({"major": "GW", "minor": "nat_gw"}, None)

    items = dynamodb_items()
    assert len(items) == 1
    assert items[0]["ResourceID"] == nat_gateway_id
    assert items[0]["Creator"] == "carol@example.com"


def test_busy_nat_gateway_is_not_flagged(subnet, backdate, dynamodb_items):
    import nat_gw as nat_gw_module

    nat_gateway_id = _create_nat_gateway(
        subnet, [{"Key": "creator", "Value": "frank@example.com"}])
    backdate.nat_gateway(nat_gateway_id, days=30)
    _put_connection_count(nat_gateway_id, 50)

    nat_gw_module.main_handler({"major": "GW", "minor": "nat_gw"}, None)

    assert dynamodb_items() == []


def test_stale_false_tagged_nat_gateway_is_excluded(subnet, backdate, dynamodb_items):
    import nat_gw as nat_gw_module

    nat_gateway_id = _create_nat_gateway(subnet, [
        {"Key": "creator", "Value": "grace@example.com"},
        {"Key": "stale", "Value": "false"},
    ])
    backdate.nat_gateway(nat_gateway_id, days=30)
    # Deliberately no connection-count metric put — same reasoning as
    # the other two detectors' exclusion tests.

    nat_gw_module.main_handler({"major": "GW", "minor": "nat_gw"}, None)

    assert dynamodb_items() == []
