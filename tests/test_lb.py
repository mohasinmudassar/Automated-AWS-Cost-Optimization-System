from datetime import datetime, timedelta, timezone

import boto3
import pytest


@pytest.fixture
def subnets(aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24",
                            AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.2.0/24",
                            AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    return vpc, [s1, s2]


def _create_lb(vpc, subnet_ids, tags):
    elbv2 = boto3.client("elbv2", region_name="us-east-1")
    lb = elbv2.create_load_balancer(
        Name="test-lb", Subnets=subnet_ids, Type="application", Tags=tags,
    )["LoadBalancers"][0]
    tg = elbv2.create_target_group(
        Name="test-tg", Protocol="HTTP", Port=80, VpcId=vpc, TargetType="instance",
    )["TargetGroups"][0]
    elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    return lb["LoadBalancerArn"]


def _put_request_count(lb_arn, value):
    dimension_value = lb_arn.split(":loadbalancer/")[1]
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(Namespace="AWS/ApplicationELB", MetricData=[{
        "MetricName": "RequestCount",
        "Dimensions": [{"Name": "LoadBalancer", "Value": dimension_value}],
        "Timestamp": datetime.now(timezone.utc) - timedelta(minutes=2),
        "Value": value,
        "Unit": "Count",
    }])


def test_idle_lb_is_flagged(subnets, backdate, dynamodb_items):
    import lb as lb_module

    vpc, subnet_ids = subnets
    lb_arn = _create_lb(vpc, subnet_ids, [
        {"Key": "creator", "Value": "bob@example.com"},
        {"Key": "Name", "Value": "lb-1"},
    ])
    backdate.load_balancer(lb_arn, days=30)
    _put_request_count(lb_arn, 5)

    lb_module.main_handler({"major": "LB"}, None)

    items = dynamodb_items()
    assert len(items) == 1
    assert items[0]["Creator"] == "bob@example.com"
    assert items[0]["Tags"] == {"creator": "bob@example.com", "Name": "lb-1"}
    assert "RequestCount 5" in items[0]["Metrics"]
    assert "RequestCount <=" in items[0]["ThresholdCrossed"]


def test_stale_false_tagged_lb_is_excluded(subnets, backdate, dynamodb_items):
    import lb as lb_module

    vpc, subnet_ids = subnets
    lb_arn = _create_lb(vpc, subnet_ids, [
        {"Key": "creator", "Value": "erin@example.com"},
        {"Key": "stale", "Value": "false"},
    ])
    backdate.load_balancer(lb_arn, days=30)

    lb_module.main_handler({"major": "LB"}, None)

    assert dynamodb_items() == []
