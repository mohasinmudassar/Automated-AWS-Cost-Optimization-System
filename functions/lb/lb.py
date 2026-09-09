import sys
import json
import logging
from datetime import datetime, timedelta, timezone
from schema import config, import_schema
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
if len(logging.getLogger().handlers) > 0:
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s: %(levelname)s: %(message)s')


spacer = "_" * 100

TIME_FRAME = 7
PERIOD = 86400 * TIME_FRAME
default_region = config.AWS_REGION

dynamodb = boto3.client('dynamodb', region_name=default_region)
table_name = config.TABLE_NAME


def get_creator_from_cloudtrail_ec2(resource_creation_time, region, resource_id):
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)

    start_time = resource_creation_time
    end_time = datetime.now()

    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'ResourceName', 'AttributeValue': resource_id},
        ],
        StartTime=start_time,
        EndTime=end_time
    )

    events = response.get('Events', [])
    for event in events:
        if event['EventName'] == "CreateLoadBalancer":
            user_identity = json.loads(event['CloudTrailEvent'])[
                'userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None


def get_metrics(cloudwatch_client, resource_type_major, resource_type_minor, lb_resource_id, start_time, end_time):
    details = import_schema.get_data(resource_type_major)[
        'Metrics'][resource_type_minor]
    query = {}
    metric_data_queries = []
    for key, _ in details.items():
        query = {
            "Id": details[key]['Metric_ID'],
            "MetricStat": {
                "Metric": {
                    "Namespace": details[key]["Metric_Namespace"],
                    "MetricName": details[key]["Metric_Name"],
                    "Dimensions": [
                        {
                            "Name": "LoadBalancer",
                            "Value": lb_resource_id
                        },
                    ]
                },
                "Period": PERIOD,
                "Stat": details[key]["Stat"],
                "Unit": details[key]["Unit"]
            },
        }
        metric_data_queries.append(query)
    response = cloudwatch_client.get_metric_data(
        StartTime=start_time,
        EndTime=end_time,
        MetricDataQueries=metric_data_queries,
    )
    return response


def main_handler(event, context):
    email_candidates = {}
    info_candidates = []
    resource_type_major = event['major']

    ec2_client = boto3.client('ec2', region_name=default_region)
    regions = [region['RegionName']
               for region in ec2_client.describe_regions()['Regions']]

    for region in regions:
        client = boto3.client("elbv2", region_name=region)
        cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        paginator = client.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for load_balancer in page["LoadBalancers"]:
                lb_name = load_balancer["LoadBalancerName"]
                lb_type = load_balancer["Type"]
                lb_creation_time = load_balancer['CreatedTime']

                lb_age = datetime.now(
                    lb_creation_time.tzinfo) - lb_creation_time
                lb_age_days = lb_age.days

                lb_resource_id = load_balancer["LoadBalancerArn"].split(
                    "/", maxsplit=1)[1]

                target_groups = client.describe_target_groups(
                    LoadBalancerArn=load_balancer["LoadBalancerArn"])
                listeners = [tg["TargetGroupName"]
                             for tg in target_groups["TargetGroups"]]

                tags = client.describe_tags(
                    ResourceArns=[load_balancer["LoadBalancerArn"]])
                creator = None
                tag_dicts = tags['TagDescriptions'][0]['Tags']
                tags_dict = {t['Key']: t['Value'] for t in tag_dicts}
                for x in tag_dicts:
                    if any('creator' == v for v in x.values()):
                        creator = x['Value']
                if creator:
                    if creator not in email_candidates:
                        email_candidates[creator] = []
                else:
                    creator = get_creator_from_cloudtrail_ec2(
                        lb_creation_time, region, load_balancer["LoadBalancerArn"])
                    if creator not in email_candidates:
                        email_candidates[creator] = []

                stale_tag_present = any(
                    tag['Key'] == 'stale' and tag['Value'] == 'false' for tag in tag_dicts)
                if stale_tag_present:
                    info_candidates.append((lb_name, lb_type, lb_age, region, creator,
                                           listeners, "Resource tagged as not stale by owner", "None"))
                    continue

                if lb_age_days >= TIME_FRAME:
                    if listeners:
                        end_time = datetime.now(timezone.utc) + timedelta(minutes=1)
                        start_time = end_time - timedelta(days=TIME_FRAME)
                        response = get_metrics(
                            cloudwatch_client, resource_type_major, lb_type, lb_resource_id, start_time, end_time)

                        request_count_list = response['MetricDataResults'][0]['Values']

                        if request_count_list:
                            request_count = response['MetricDataResults'][0]['Values'][0]

                            threshold_text = (
                                f"RequestCount <= {config.LB_REQUEST_COUNT_THRESHOLD} "
                                f"over {TIME_FRAME} days")

                            if request_count > config.LB_REQUEST_COUNT_THRESHOLD:
                                status = "Not stale"
                                logger.info(
                                    f"Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, Requests: {request_count}")
                            else:
                                status = "stale"
                                email_candidates[creator].append({
                                    "resource_id": lb_resource_id,
                                    "region": region,
                                    "status_reason": "idle",
                                    "resource_type": resource_type_major,
                                    "tags": tags_dict,
                                    "resource_arn": load_balancer["LoadBalancerArn"],
                                    "metrics": f"RequestCount {request_count} over the last {TIME_FRAME} days",
                                    "threshold_crossed": threshold_text,
                                })
                                logger.info(
                                    f"Stale LB Detected: Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, Requests: {request_count}")

                            info_candidates.append(
                                (lb_name, lb_type, lb_age, region, creator, listeners, request_count_list, status))
                        else:
                            email_candidates[creator].append({
                                "resource_id": lb_resource_id,
                                "region": region,
                                "status_reason": "idle",
                                "resource_type": resource_type_major,
                                "tags": tags_dict,
                                "resource_arn": load_balancer["LoadBalancerArn"],
                                "metrics": f"No CloudWatch data returned over the last {TIME_FRAME} days",
                                "threshold_crossed": (
                                    f"RequestCount <= {config.LB_REQUEST_COUNT_THRESHOLD} "
                                    f"over {TIME_FRAME} days"),
                            })
                            logger.info(
                                f"Stale LB Detected: Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, No Request Count")
                            info_candidates.append(
                                (lb_name, lb_type, lb_age, region, creator, listeners, "No Values Returned", "stale"))
                    else:
                        info_candidates.append(
                            (lb_name, lb_type, lb_age, region, creator, listeners, "No Listeners Attached", "misconfigured"))
                        email_candidates[creator].append({
                            "resource_id": lb_resource_id,
                            "region": region,
                            "status_reason": "misconfigured",
                            "resource_type": resource_type_major,
                            "tags": tags_dict,
                            "resource_arn": load_balancer["LoadBalancerArn"],
                            "metrics": "No listeners/target groups attached",
                            "threshold_crossed": "N/A — flagged for missing listeners, not idle traffic",
                        })
                else:
                    info_candidates.append((lb_name, lb_type, lb_age, region, creator,
                                           listeners, f"Resource Age less than {TIME_FRAME} days", "None"))

    BODY_TEXT = ""
    sns_client = boto3.client('sns', region_name=default_region)
    for resource in info_candidates:
        BODY_TEXT += (
            f"\n{spacer}"
            f"\n--> LB_Name: {resource[0]}, LB_Type: {resource[1]}, Age: {resource[2]} Region: {resource[3]}, Owner: {resource[4]}"
            f"\nListeners: {resource[5]}"
            f"\nRequest Count: {resource[6]}"
            f"\nStatus: {resource[7]}"
        )
    try:
        sns_client.publish(
            TopicArn=config.SNS_TOPIC_ARN,
            Message=BODY_TEXT,
            Subject='Info',
        )
    except ClientError:
        logger.exception('Could not publish message to the topic.')

    for creator, idle_resources in email_candidates.items():
        if creator is not None:
            BODY_TEXT = ""
            if idle_resources:
                for resource in idle_resources:
                    if resource["status_reason"] == "idle":
                        instruction = "delete it if you don't need it"
                    else:
                        instruction = "configure it properly or delete it if you don't need it"
                    try:
                        lb_resource_id = resource["resource_id"].split('/')[2]
                        dynamodb.put_item(
                            TableName=table_name,
                            Item={
                                'Creator': {'S': creator},
                                'ResourceID': {'S': lb_resource_id},
                                'Type': {'S': resource["resource_type"]},
                                'Region': {'S': resource["region"]},
                                'Deletion_Status': {'S': "Marked"},
                                'Identification_Time': {'S': datetime.utcnow().strftime("%d-%m-%Y, %H:%M:%S")},
                                'Tags': {'M': {k: {'S': v} for k, v in resource["tags"].items()}},
                                'Metrics': {'S': resource["metrics"]},
                                'ThresholdCrossed': {'S': resource["threshold_crossed"]},
                                'ResourceArn': {'S': resource["resource_arn"]},
                            }
                        )
                        logger.info(
                            f"Stored stale LB ({lb_resource_id}, {resource['region']}, {resource['status_reason']}) in DynamoDB")
                    except ClientError as e:
                        logger.exception(f"Error storing LB in DynamoDB: {e}")

                    BODY_TEXT += (
                        f"\n--> load balancer named {resource['resource_id']}, Owner: {creator}  Region: {resource['region']}"
                        f" has been identified as {resource['status_reason']} resource"
                        f"\nPlease {instruction}"
                    )

                SENDER = config.SES_SENDER
                RECIPIENT = creator
                SUBJECT = "Stale resource identified"
                CHARSET = "UTF-8"

                ses_client = boto3.client('ses', region_name=default_region)
                try:
                    ses_client.send_email(
                        Destination={'ToAddresses': [RECIPIENT]},
                        Message={
                            'Body': {'Text': {'Charset': CHARSET, 'Data': BODY_TEXT}},
                            'Subject': {'Charset': CHARSET, 'Data': SUBJECT},
                        },
                        Source=SENDER,
                    )
                except ClientError as e:
                    logger.exception(e.response['Error']['Message'])
