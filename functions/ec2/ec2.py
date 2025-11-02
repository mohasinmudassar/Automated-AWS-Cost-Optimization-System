import os
import sys
import json
import logging
from datetime import datetime, timedelta
from schema import import_schema
import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------
# LOGGING CONFIGURATION
# ---------------------------------------------------------------------
# Set up logging so the Lambda prints timestamps and levels in CloudWatch
logger = logging.getLogger()
if len(logging.getLogger().handlers) > 0:
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s: %(levelname)s: %(message)s')


# ---------------------------------------------------------------------
# GLOBAL CONFIGURATION / HARDCODED VARIABLES
# ---------------------------------------------------------------------
spacer = "_" * 100
default_region = 'AWS_REGION, ap-southeast-1'

# ---------------------------------------------------------------------
# DYNAMODB SETUP
# ---------------------------------------------------------------------
dynamodb = boto3.client('dynamodb', region_name=default_region)

table_name = 'StaleResourcesTesting'

# Define table schema and throughput (hardcoded)
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

# Attempt to create DynamoDB table if it doesn't exist
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
# FUNCTION: schedule_deletion_lambda
# ---------------------------------------------------------------------
# This function schedules another Lambda (deletion lambda) via EventBridge
# to run automatically at a future time (here ~7 days later).
def schedule_deletion_lambda(resource_type, table_name, function_name, function_arn, rule_name):
    lambda_client = boto3.client('lambda', region_name=default_region)
    eventbridge = boto3.client('events', region_name=default_region)

    # Schedule deletion ~7 days later (10050 minutes)
    current_time = datetime.utcnow()
    scheduled_time = current_time + timedelta(minutes=10050)

    # IAM permission and rule config
    statement_id = 'event'
    action = 'lambda:InvokeFunction'
    principal = 'events.amazonaws.com'
    input_data = {
        "table_name": table_name,
        "type": resource_type
    }

    try:
        # Create EventBridge rule with a cron expression for scheduled execution
        eventbridge.put_rule(
            Name=rule_name,
            ScheduleExpression=f'cron({scheduled_time.minute} {scheduled_time.hour} {scheduled_time.day} {scheduled_time.month} ? {scheduled_time.year})',
            State='ENABLED'
        )

        # Attach deletion lambda as the rule target
        eventbridge.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': function_name,
                    'Arn': function_arn,
                    'Input': json.dumps(input_data)
                }
            ]
        )

        # Grant EventBridge permission to invoke the lambda
        response = eventbridge.describe_rule(Name=rule_name)
        source_arn = response['Arn']
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action=action,
            Principal=principal,
            SourceArn=source_arn
        )
        return scheduled_time.strftime("%d-%m-%Y, %H:%M:%S")
    except Exception as e:
        logger.exception(f"Error while scheduling deletion lambda: {e}")
        return False


# ---------------------------------------------------------------------
# FUNCTION: get_creator_from_cloudtrail_ec2
# ---------------------------------------------------------------------
# Looks up CloudTrail events to find who created an EC2 instance
def get_creator_from_cloudtrail_ec2(resource_creation_time, region, resource_id):
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)

    start_time = resource_creation_time
    end_time = datetime.now()

    # Search for resource creation events
    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'ResourceName', 'AttributeValue': resource_id},
        ],
        StartTime=start_time,
        EndTime=end_time
    )

    # Parse and return creator (username) if found
    events = response.get('Events', [])
    for event in events:
        if event['EventName'] == "RunInstances":  # Filter only EC2 launch events
            user_identity = json.loads(event['CloudTrailEvent'])[
                'userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None


# ---------------------------------------------------------------------
# FUNCTION: get_metrics
# ---------------------------------------------------------------------
# Fetches EC2 metrics (CPU, NetworkIn, NetworkOut) from CloudWatch
def get_metrics(cloudwatch_client, resource_type_major, resource_type_minor, instance_resource_id, start_time, end_time, PERIOD):
    details = import_schema.get_data(resource_type_major)[
        'Metrics'][resource_type_minor]
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
                            "Name": "InstanceId",
                            "Value": instance_resource_id
                        },
                    ]
                },
                "Period": PERIOD,             # Uses time frame in seconds
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
# MAIN HANDLER FUNCTION (entry point for Lambda)
# ---------------------------------------------------------------------
def main_handler(event, context):
    """
    High-level flow:
    1. Iterate over all regions
    2. For each EC2 instance:
        - Find creator
        - Check if tagged as non-stale
        - Fetch CloudWatch metrics
        - Decide stale / active
    3. Store stale resources in DynamoDB
    4. Notify owners via SES and summary via SNS
    5. Schedule deletion Lambda
    """

    # Initialize state tracking
    email_candidates = {}  # Owner -> list of stale resources
    info_candidates = []   # Summary report entries

    # Extract parameters from event
    resource_type_major = event['major']
    resource_type_minor = event['minor']
    deletion_lambda_name = event['deletion_lambda_name']
    deletion_lambda_arn = event['deletion_lambda_arn']
    deletion_lambda_rule_name = event['deletion_lambda_rule_name']
    TIME_FRAME = event['time_frame']  # days
    PERIOD = 86400 * TIME_FRAME       # seconds

    # -----------------------------------------------------------------
    # Step 1: Get all available regions and iterate through them
    # -----------------------------------------------------------------
    ec2_client = boto3.client('ec2', region_name=default_region)
    regions = [region['RegionName']
               for region in ec2_client.describe_regions()['Regions']]

    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        instances = ec2.describe_instances()

        # -----------------------------------------------------------------
        # Step 2: Iterate through EC2 instances in this region
        # -----------------------------------------------------------------
        for reservation in instances['Reservations']:
            for instance_info in reservation['Instances']:
                instance_id = instance_info['InstanceId']
                instance_creation_time = instance_info['LaunchTime']
                instance_age = datetime.now(
                    instance_creation_time.tzinfo) - instance_creation_time
                instance_age_days = instance_age.days

                # Retrieve tags to identify creator or status
                ec2_tags = ec2.describe_tags(
                    Filters=[{'Name': 'resource-id', 'Values': [instance_id]}])
                creator = None
                status = None

                # Find creator tag (if available)
                for tag in ec2_tags['Tags']:
                    if tag['Key'] == 'creator':
                        creator = tag['Value']
                        break

                # Track creator in map
                if creator:
                    email_candidates.setdefault(creator, [])
                else:
                    # fallback to CloudTrail lookup
                    creator = get_creator_from_cloudtrail_ec2(
                        instance_creation_time, region, instance_id)
                    email_candidates.setdefault(creator, [])

                # -----------------------------------------------------------------
                # Step 3: Skip instances explicitly marked as non-stale
                # -----------------------------------------------------------------
                # ❗ Hardcoded tag key/value
                stale_tag_present = any(
                    tag['Key'] == 'stale' and tag['Value'] == 'false' for tag in ec2_tags)
                if stale_tag_present:
                    info_candidates.append((instance_id, instance_age, region, creator,
                                            "Resource tagged as not stale by owner",
                                            "Resource tagged as not stale by owner",
                                            "Resource tagged as not stale by owner", "None"))
                    continue

                # -----------------------------------------------------------------
                # Step 4: Evaluate activity if resource is older than threshold
                # -----------------------------------------------------------------
                if instance_age_days >= TIME_FRAME:
                    end_time = datetime.now()
                    start_time = end_time - timedelta(days=TIME_FRAME)
                    response = get_metrics(cloudwatch_client, resource_type_major, resource_type_minor,
                                           instance_id, start_time, end_time, PERIOD)

                    network_in_data = response['MetricDataResults'][0]['Values']
                    network_out_data = response['MetricDataResults'][1]['Values']
                    cpu_utilization_data = response['MetricDataResults'][2]['Values']

                    # Evaluate activity based on thresholds
                    if network_in_data or network_out_data or cpu_utilization_data:
                        network_in_data = network_in_data[0] if network_in_data else 0
                        network_out_data = network_out_data[0] if network_out_data else 0
                        cpu_utilization_data = cpu_utilization_data[0] if cpu_utilization_data else 0

                        if (network_in_data < 5 * 1024 * 1024 and network_out_data < 5 * 1024 * 1024) or cpu_utilization_data < 10:
                            status = "stale"
                            email_candidates[creator].append(
                                (instance_id, region, resource_type_major))
                            logger.info(
                                f"Stale Instance Detected: {instance_id}, Owner: {creator}, Region: {region}, CPU: {cpu_utilization_data}")
                        else:
                            status = "Not stale"
                            logger.info(
                                f"Active Instance: {instance_id}, Owner: {creator}, Region: {region}, CPU: {cpu_utilization_data}")

                        info_candidates.append((instance_id, instance_age, region, creator,
                                                network_in_data / 1048576, network_out_data / 1048576,
                                                cpu_utilization_data, status))
                    else:
                        # No data means probably idle
                        email_candidates[creator].append(
                            (instance_id, region, resource_type_major))
                        info_candidates.append((instance_id, instance_age, region, creator,
                                                "No Values Returned", "No Values Returned", "No Values Returned", "stale"))
                else:
                    # Skip if instance age is less than the defined window
                    info_candidates.append((instance_id, instance_age, region, creator,
                                            f"Resource Age less than {TIME_FRAME} days",
                                            f"Resource Age less than {TIME_FRAME} days",
                                            f"Resource Age less than {TIME_FRAME} days", "None"))

    # -----------------------------------------------------------------
    # Step 5: Publish summary of analysis to SNS topic
    # -----------------------------------------------------------------
    BODY_TEXT = ""
    sns_client = boto3.client('sns', region_name=default_region)
    for resource in info_candidates:
        BODY_TEXT += (f"\n{spacer}"
                      f"\n--> EC2 instance: {resource[0]}, Age: {resource[1]}, Region: {resource[2]}, Owner: {resource[3]}"
                      f"\nNetworkIn: {resource[4]}, NetworkOut: {resource[5]}, CPU: {resource[6]}"
                      f"\nStatus: {resource[7]}"
                      f"\n{spacer}")
    try:
        sns_client.publish(
            TopicArn='arn:aws:sns:ap-southeast-1:737457451118:stale-resource-info',
            Message=BODY_TEXT,
            Subject='Info',
        )
    except ClientError:
        logger.exception('Could not publish message to the topic.')

    # -----------------------------------------------------------------
    # Step 6: Store stale results to DynamoDB and notify owners via SES
    # -----------------------------------------------------------------
    for creator, idle_resources in email_candidates.items():
        if creator:
            BODY_TEXT = ""
            for resource in idle_resources:
                try:
                    dynamodb.put_item(
                        TableName=table_name,
                        Item={
                            'Creator': {'S': creator},
                            'ResourceID': {'S': resource[0]},
                            'Type': {'S': resource[2]},
                            'Region': {'S': resource[1]},
                            'Deletion_Status': {'S': "Marked"},
                            'Identification_Time': {'S': datetime.utcnow().strftime("%d-%m-%Y, %H:%M:%S")}
                        }
                    )
                    logger.info(f"Stored stale EC2 {resource} in DynamoDB")
                except ClientError as e:
                    logger.exception(f"Error storing EC2 in DynamoDB: {e}")

                # Prepare email content
                BODY_TEXT += (f"\n--> EC2 instance: {resource[0]}, Owner: {creator} Region: {resource[1]}"
                              "\n identified as a stale resource"
                              "\n Delete it if not needed; it will be automatically deleted after 7 days."
                              "\n If still needed, tag it with: Key='Stale', Value='false'")

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

    # -----------------------------------------------------------------
    # Step 7: Schedule automatic deletion Lambda via EventBridge
    # -----------------------------------------------------------------
    response = schedule_deletion_lambda(resource_type_major, table_name, deletion_lambda_name,
                                        deletion_lambda_arn, deletion_lambda_rule_name)
    BODY_TEXT = ("Unable to schedule deletion lambda" if not response
                 else f"Deletion lambda for {resource_type_major} scheduled at {response} (UTC Time)")

    try:
        sns_client.publish(
            TopicArn='arn:stale-resource-info',
            Message=BODY_TEXT,
            Subject='Info',
        )
    except ClientError:
        logger.exception('Could not publish message to the topic.')
