from datetime import datetime, timezone

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
    # AWS/ApplicationELB dimensions use the ARN suffix after "loadbalancer/",
    # e.g. "app/test-lb/1234567890abcdef" — matches lb.py's own
    # lb_resource_id = LoadBalancerArn.split("/", maxsplit=1)[1].
    dimension_value = lb_arn.split(":loadbalancer/")[1]
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_data(Namespace="AWS/ApplicationELB", MetricData=[{
        "MetricName": "RequestCount",
        "Dimensions": [{"Name": "LoadBalancer", "Value": dimension_value}],
        "Timestamp": datetime.now(timezone.utc),
        "Value": value,
        "Unit": "Count",
    }])


def test_idle_lb_is_flagged(subnets, backdate, dynamodb_items):
    import lb as lb_module

    vpc, subnet_ids = subnets
    lb_arn = _create_lb(
        vpc, subnet_ids, [{"Key": "creator", "Value": "bob@example.com"}])
    backdate.load_balancer(lb_arn, days=30)
    _put_request_count(lb_arn, 5)

    lb_module.main_handler({"major": "LB"}, None)

    items = dynamodb_items()
    assert len(items) == 1
    assert items[0]["Creator"] == "bob@example.com"


def test_busy_lb_is_not_flagged(subnets, backdate, dynamodb_items):
    import lb as lb_module

    vpc, subnet_ids = subnets
    lb_arn = _create_lb(
        vpc, subnet_ids, [{"Key": "creator", "Value": "dave@example.com"}])
    backdate.load_balancer(lb_arn, days=30)
    _put_request_count(lb_arn, 5000)

    lb_module.main_handler({"major": "LB"}, None)

    assert dynamodb_items() == []


def test_stale_false_tagged_lb_is_excluded(subnets, backdate, dynamodb_items):
    import lb as lb_module

    vpc, subnet_ids = subnets
    lb_arn = _create_lb(vpc, subnet_ids, [
        {"Key": "creator", "Value": "erin@example.com"},
        {"Key": "stale", "Value": "false"},
    ])
    backdate.load_balancer(lb_arn, days=30)
    # Deliberately no RequestCount metric put — proves the exclusion
    # happens before any metric evaluation, not just "no data => not
    # flagged" by coincidence (this handler treats no data as stale).

    lb_module.main_handler({"major": "LB"}, None)

    assert dynamodb_items() == []
