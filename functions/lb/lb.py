import os
import sys
import json
import logging
from datetime import datetime, timedelta
from schema import import_schema
import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------
logger = logging.getLogger()
if len(logging.getLogger().handlers) > 0:
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(levelname)s: %(message)s')


# ---------------------------------------------------------------------
# GLOBAL VARIABLES / HARDCODED VALUES
# ---------------------------------------------------------------------
spacer = "_" * 100

TIME_FRAME = 7                     
PERIOD = 86400 * TIME_FRAME        # Metric period (seconds) — derived from TIME_FRAME
default_region = 'ap-southeast-1' 

# ---------------------------------------------------------------------
# DynamoDB SETUP
# ---------------------------------------------------------------------
# 
dynamodb = boto3.client('dynamodb', region_name=default_region)
table_name = 'StaleResourcesTesting' 

key_schema = [
    {'AttributeName': 'ResourceID', 'KeyType': 'HASH'},
    {'AttributeName': 'Type', 'KeyType': 'RANGE'}
]
attribute_definitions = [
    {'AttributeName': 'ResourceID', 'AttributeType': 'S'},
    {'AttributeName': 'Type', 'AttributeType': 'S'}
]
provisioned_throughput = {
    'ReadCapacityUnits': 5,   
    'WriteCapacityUnits': 5   
}

# Create table if missing
try:
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attribute_definitions,
        ProvisionedThroughput=provisioned_throughput
    )
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceInUseException':
        logger.info(f"Table {table_name} already exists.")
    else:
        raise


# ---------------------------------------------------------------------
# Function: Find creator of a Load Balancer from CloudTrail
# ---------------------------------------------------------------------
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
        # Looks specifically for 'CreateLoadBalancer' event to find the user
        if event['EventName'] == "CreateLoadBalancer":
            user_identity = json.loads(event['CloudTrailEvent'])['userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None


# ---------------------------------------------------------------------
# Function: Pull CloudWatch metrics for a Load Balancer
# ---------------------------------------------------------------------
def get_metrics(cloudwatch_client, resource_type_major, resource_type_minor, lb_resource_id, start_time, end_time):
    details = import_schema.get_data(resource_type_major)['Metrics'][resource_type_minor]
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
                "Period": PERIOD,        # Uses global hardcoded PERIOD (7 days * 86400)
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


# ---------------------------------------------------------------------
# MAIN HANDLER FUNCTION
# ---------------------------------------------------------------------
def main_handler(event, context):
    """
    Main steps:
    1) Enumerate all AWS regions
    2) Fetch all Load Balancers in each region
    3) Determine creator (tag or CloudTrail)
    4) Check CloudWatch metrics for activity in last TIME_FRAME days
    5) Classify as 'stale' or 'active'
    6) Store stale results in DynamoDB and send notifications via SNS + SES
    """
    email_candidates = {}   # Holds creators → list of their stale LBs
    info_candidates = []    # For SNS summary
    resource_type_major = event['major']

    # -----------------------------------------------------------------
    # Step 1: List all AWS regions
    # -----------------------------------------------------------------
    ec2_client = boto3.client('ec2', region_name=default_region)
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # -----------------------------------------------------------------
    # Step 2: Loop through all regions to analyze LBs
    # -----------------------------------------------------------------
    for region in regions:
        client = boto3.client("elbv2", region_name=region)
        cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        paginator = client.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for load_balancer in page["LoadBalancers"]:
                lb_name = load_balancer["LoadBalancerName"]
                lb_type = load_balancer["Type"]
                lb_creation_time = load_balancer['CreatedTime']

                # Compute LB age
                lb_age = datetime.now(lb_creation_time.tzinfo) - lb_creation_time
                lb_age_days = lb_age.days

                lb_resource_id = load_balancer["LoadBalancerArn"].split("/", maxsplit=1)[1]

                # -----------------------------------------------------------------
                # Step 3: Get Target Groups (listeners) for the LB
                # -----------------------------------------------------------------
                target_groups = client.describe_target_groups(LoadBalancerArn=load_balancer["LoadBalancerArn"])
                listeners = [tg["TargetGroupName"] for tg in target_groups["TargetGroups"]]

                # -----------------------------------------------------------------
                # Step 4: Find creator tag or fallback to CloudTrail
                # -----------------------------------------------------------------
                tags = client.describe_tags(ResourceArns=[load_balancer["LoadBalancerArn"]])
                creator = None
                tag_dicts = tags['TagDescriptions'][0]['Tags']
                for x in tag_dicts:
                    if any('creator' == v for v in x.values()): 
                        creator = x['Value']
                if creator:
                    if creator not in email_candidates:
                        email_candidates[creator] = []
                else:
                    # fallback via CloudTrail lookup
                    creator = get_creator_from_cloudtrail_ec2(lb_creation_time, region, load_balancer["LoadBalancerArn"])
                    if creator not in email_candidates:
                        email_candidates[creator] = []

                # -----------------------------------------------------------------
                # Step 5: Evaluate LB activity if older than TIME_FRAME
                # -----------------------------------------------------------------
                if lb_age_days >= TIME_FRAME:
                    if listeners:
                        end_time = datetime.now()
                        start_time = end_time - timedelta(days=TIME_FRAME)
                        response = get_metrics(cloudwatch_client, resource_type_major, lb_type, lb_resource_id, start_time, end_time)

                        request_count_list = response['MetricDataResults'][1]['Values']

                        if request_count_list:
                            request_count = response['MetricDataResults'][1]['Values'][0]

                            if request_count > 1000:
                                status = "Not stale"
                                logger.info(f"Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, Requests: {request_count}")
                            else:
                                status = "stale"
                                email_candidates[creator].append((lb_name, lb_resource_id, region, "idle", lb_type, resource_type_major))
                                logger.info(f"Stale LB Detected: Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, Requests: {request_count}")

                            info_candidates.append((lb_name, lb_type, lb_age, region, creator, listeners, request_count_list, status))
                        else:
                            # No metric data → consider stale
                            email_candidates[creator].append((lb_name, lb_resource_id, region, "idle", lb_type, resource_type_major))
                            logger.info(f"Stale LB Detected: Name: {lb_name}, Owner: {creator}, Region: {region}, Age: {lb_age}, No Request Count")
                            info_candidates.append((lb_name, lb_type, lb_age, region, creator, listeners, "No Values Returned", "stale"))
                    else:
                        # LBs without listeners are misconfigured
                        info_candidates.append((lb_name, lb_type, lb_age, region, creator, listeners, "No Listeners Attached", "misconfigured"))
                        email_candidates[creator].append((lb_name, lb_resource_id, region, "misconfigured", lb_type, resource_type_major))
                else:
                    # Skip young resources
                    info_candidates.append((lb_name, lb_type, lb_age, region, creator, listeners, f"Resource Age less than {TIME_FRAME} days", "None"))

    # -----------------------------------------------------------------
    # Step 6: Publish overall results to SNS
    # -----------------------------------------------------------------
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
            TopicArn='arn:stale-resource-info',
            Message=BODY_TEXT,
            Subject='Info',
        )
    except ClientError:
        logger.exception('Could not publish message to the topic.')

    # -----------------------------------------------------------------
    # Step 7: Store stale results to DynamoDB and send SES emails
    # -----------------------------------------------------------------
    for creator, idle_resources in email_candidates.items():
        if creator is not None:
            BODY_TEXT = ""
            if idle_resources:
                for resource in idle_resources:
                    if resource[2] == "idle":
                        instruction = "delete it if you don't need it"
                    else:
                        instruction = "configure it properly or delete it if you don't need it"
                    try:
                        lb_resource_id = resource[1].split('/')[2]
                        dynamodb.put_item(
                            TableName=table_name,
                            Item={
                                'Creator': {'S': creator},
                                'ResourceID': {'S': lb_resource_id},
                                'Type': {'S': resource[5]},
                                'Region': {'S': resource[2]},
                                'Deletion_Status': {'S': "Marked"},
                            }
                        )
                        logger.info(f"Stored stale LB ({lb_resource_id}, {resource[2]}, {resource[3]}) in DynamoDB")
                    except ClientError as e:
                        logger.exception(f"Error storing LB in DynamoDB: {e}")

                    BODY_TEXT += (
                        f"\n--> {resource[4]} load balancer named {resource[0]}, Owner: {creator}  Region: {resource[2]}"
                        f" has been identified as {resource[3]} resource"
                        f"\nPlease {instruction} or it will be automatically deleted"
                    )
                SENDER = "sender@gmail.com"
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