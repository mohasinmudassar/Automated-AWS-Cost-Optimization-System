import os
import sys
import json
import logging
from datetime import datetime, timedelta
from schema import import_schema
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
PERIOD = 86400 * TIME_FRAME  # Convert days to seconds


default_region = 'AWS_REGION, ap-southeast-1'


# Connect to DynamoDB
dynamodb = boto3.client('dynamodb', region_name=default_region)

table_name = 'StaleResourcesTesting'

# Define DynamoDB schema
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

# Create DynamoDB table if it does not exist
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


def get_creator_from_cloudtrail_ec2(resource_creation_time, region, resource_id):
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)

    start_time = resource_creation_time
    end_time = datetime.now()

    # Look up creation events for the given NAT Gateway ID
    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'ResourceName', 'AttributeValue': resource_id},
        ],
        StartTime=start_time,
        EndTime=end_time
    )

    events = response.get('Events', [])
    for event in events:

        if event['EventName'] == "CreateNatGateway":
            user_identity = json.loads(event['CloudTrailEvent'])[
                'userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None


# Fetches NAT Gateway CloudWatch metrics such as connection attempts.
def get_metrics(cloudwatch_client, resource_type_major, resource_type_minor, gw_resource_id, start_time, end_time):
    details = import_schema.get_data(resource_type_major)[
        'Metrics'][resource_type_minor]
    metric_data_queries = []

    # Build CloudWatch metric queries based on schema definitions
    for key, _ in details.items():
        query = {
            "Id": details[key]['Metric_ID'],
            "MetricStat": {
                "Metric": {
                    "Namespace": details[key]["Metric_Namespace"],
                    "MetricName": details[key]["Metric_Name"],
                    "Dimensions": [
                        {
                            "Name": "NatGatewayId",
                            "Value": gw_resource_id
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
    """
    Main workflow:
    1. Iterate over all AWS regions.
    2. For each region, list all NAT Gateways.
    3. Determine the creator (via tag or CloudTrail).
    4. Check CloudWatch metrics to find stale gateways.
    5. Log and store stale resources in DynamoDB.
    6. Notify owners via SES and summary via SNS.
    """
    email_candidates = {}
    info_candidates = []

    # Extract parameters from event payload
    resource_type_major = event['major']
    resource_type_minor = event['minor']

    ec2_client = boto3.client('ec2', region_name=default_region)
    regions = [region['RegionName']
               for region in ec2_client.describe_regions()['Regions']]

    for region in regions:
        cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        ec2 = boto3.client('ec2', region_name=region)

        response = ec2.describe_nat_gateways()

        for nat_gateway in response['NatGateways']:
            nat_gateway_id = nat_gateway['NatGatewayId']
            nat_gateway_creation_time = nat_gateway['CreateTime']

            # Calculate age of the NAT Gateway
            nat_gateway_age = datetime.now(
                nat_gateway_creation_time.tzinfo) - nat_gateway_creation_time
            nat_gateway_age_days = nat_gateway_age.days

            # Retrieve tags to identify owner
            nat_gateway_tags = ec2.describe_tags(
                Filters=[{'Name': 'resource-id', 'Values': [nat_gateway_id]}])
            creator = None
            status = None

            for tag in nat_gateway_tags['Tags']:
                if tag['Key'] == 'creator':
                    creator = tag['Value']
                    break

            # Store or look up creator if not found
            if creator:
                email_candidates.setdefault(creator, [])
            else:
                creator = get_creator_from_cloudtrail_ec2(
                    nat_gateway_creation_time, region, nat_gateway_id)
                email_candidates.setdefault(creator, [])

            if nat_gateway_age_days >= TIME_FRAME:
                end_time = datetime.now()
                start_time = end_time - timedelta(days=TIME_FRAME)
                response = get_metrics(cloudwatch_client, resource_type_major, resource_type_minor,
                                       nat_gateway_id, start_time, end_time)

                if response['MetricDataResults'][0]['Values']:
                    connection_attempts = response['MetricDataResults'][0]['Values'][0]

                    if connection_attempts > 7:
                        status = "Not stale"
                        logger.info(
                            f"NAT Gateway: {nat_gateway_id}, Region: {region}, Owner: {creator}, Connection Attempt Count: {connection_attempts}")
                    else:
                        status = "stale"
                        email_candidates[creator].append(
                            (nat_gateway_id, region, resource_type_major))
                        logger.info(
                            f"Stale NAT Gateway detected: {nat_gateway_id}, Region: {region}, Owner: {creator}, Connection Attempt Count: {connection_attempts}")

                    info_candidates.append(
                        (nat_gateway_id, nat_gateway_age, region, creator, connection_attempts, status))
                else:
                    # No metric data indicates idle gateway
                    email_candidates[creator].append(
                        (nat_gateway_id, region, resource_type_major))
                    logger.info(
                        f"Stale NAT Gateway detected: {nat_gateway_id}, Region: {region}, Owner: {creator}, Connection Attempt Count: No Values Returned")
                    info_candidates.append(
                        (nat_gateway_id, nat_gateway_age, region, creator, "No Values Returned", "stale"))
            else:
                # Skip NAT Gateways newer than the time frame
                info_candidates.append((nat_gateway_id, nat_gateway_age, region, creator,
                                        f"Resource Age less than {TIME_FRAME} days", "None"))

    BODY_TEXT = ""
    sns_client = boto3.client('sns', region_name=default_region)
    for resource in info_candidates:
        BODY_TEXT += (f"\n{spacer}"
                      f"\n--> NAT Gateway: {resource[0]},  Age: {resource[1]}, Region: {resource[2]}, Owner: {resource[3]}"
                      f"\nConnection Attempt Count: {resource[4]}"
                      f"\nStatus: {resource[5]}")
    try:
        sns_client.publish(
            TopicArn='arn:stale-resource-info',
            Message=BODY_TEXT,
            Subject='Info',
        )
    except ClientError:
        logger.exception('Could not publish message to the topic.')

    for creator, idle_resources in email_candidates.items():
        if creator:
            BODY_TEXT = ""
            for resource in idle_resources:
                try:
                    # Insert stale NAT Gateway record into DynamoDB
                    dynamodb.put_item(
                        TableName=table_name,
                        Item={
                            'Creator': {'S': creator},
                            'ResourceID': {'S': resource[0]},
                            'Type': {'S': resource[2]},
                            'Region': {'S': resource[1]},
                            'Deletion_Status': {'S': "Marked"},
                        }
                    )
                    logger.info(
                        f"Stored stale NAT Gateway {resource} in DynamoDB")
                except ClientError as e:
                    logger.exception(
                        f"Error storing NAT Gateway in DynamoDB: {e}")

                # Prepare email body for notification
                BODY_TEXT += (f"\n--> NAT Gateway: {resource[0]}, Owner: {creator}, Region: {resource[1]}"
                              "\n has been identified as a stale resource."
                              "\n Please delete it if not needed or it will be automatically deleted soon.")

            SENDER = "creator@gmail.com"
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
        else:
            pass
