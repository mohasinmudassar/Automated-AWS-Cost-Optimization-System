import sys
import json
import logging
from datetime import datetime, timedelta
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
        if event['EventName'] == "RunInstances":
            user_identity = json.loads(event['CloudTrailEvent'])[
                'userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None


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
    resource_type_minor = event['minor']
    TIME_FRAME = event['time_frame']
    PERIOD = 86400 * TIME_FRAME

    ec2_client = boto3.client('ec2', region_name=default_region)
    regions = [region['RegionName']
               for region in ec2_client.describe_regions()['Regions']]

    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)
        cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        instances = ec2.describe_instances()

        for reservation in instances['Reservations']:
            for instance_info in reservation['Instances']:
                instance_id = instance_info['InstanceId']
                instance_creation_time = instance_info['LaunchTime']
                instance_age = datetime.now(
                    instance_creation_time.tzinfo) - instance_creation_time
                instance_age_days = instance_age.days

                ec2_tags = ec2.describe_tags(
                    Filters=[{'Name': 'resource-id', 'Values': [instance_id]}])
                tags_dict = {t['Key']: t['Value'] for t in ec2_tags['Tags']}
                creator = None
                status = None

                for tag in ec2_tags['Tags']:
                    if tag['Key'] == 'creator':
                        creator = tag['Value']
                        break

                if creator:
                    email_candidates.setdefault(creator, [])
                else:
                    creator = get_creator_from_cloudtrail_ec2(
                        instance_creation_time, region, instance_id)
                    email_candidates.setdefault(creator, [])

                stale_tag_present = any(
                    tag['Key'] == 'stale' and tag['Value'] == 'false' for tag in ec2_tags['Tags'])
                if stale_tag_present:
                    info_candidates.append((instance_id, instance_age, region, creator,
                                            "Resource tagged as not stale by owner",
                                            "Resource tagged as not stale by owner",
                                            "Resource tagged as not stale by owner", "None"))
                    continue

                if instance_age_days >= TIME_FRAME:
                    end_time = datetime.now()
                    start_time = end_time - timedelta(days=TIME_FRAME)
                    response = get_metrics(cloudwatch_client, resource_type_major, resource_type_minor,
                                           instance_id, start_time, end_time, PERIOD)

                    network_in_data = response['MetricDataResults'][0]['Values']
                    network_out_data = response['MetricDataResults'][1]['Values']
                    cpu_utilization_data = response['MetricDataResults'][2]['Values']

                    if network_in_data or network_out_data or cpu_utilization_data:
                        network_in_data = network_in_data[0] if network_in_data else 0
                        network_out_data = network_out_data[0] if network_out_data else 0
                        cpu_utilization_data = cpu_utilization_data[0] if cpu_utilization_data else 0

                        metrics_text = (
                            f"CPUUtilization {cpu_utilization_data}%, "
                            f"NetworkIn {network_in_data / 1048576:.2f} MB, "
                            f"NetworkOut {network_out_data / 1048576:.2f} MB, "
                            f"over the last {TIME_FRAME} days")
                        threshold_text = (
                            f"CPU < {config.CPU_THRESHOLD_PERCENT}% or "
                            f"Network < {config.NETWORK_THRESHOLD_BYTES / 1048576:.0f} MB, "
                            f"over {TIME_FRAME} days")

                        if (network_in_data < config.NETWORK_THRESHOLD_BYTES and network_out_data < config.NETWORK_THRESHOLD_BYTES) or cpu_utilization_data < config.CPU_THRESHOLD_PERCENT:
                            status = "stale"
                            email_candidates[creator].append({
                                "resource_id": instance_id,
                                "region": region,
                                "resource_type": resource_type_major,
                                "tags": tags_dict,
                                "metrics": metrics_text,
                                "threshold_crossed": threshold_text,
                                "instance_type": instance_info.get('InstanceType'),
                            })
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
                        email_candidates[creator].append({
                            "resource_id": instance_id,
                            "region": region,
                            "resource_type": resource_type_major,
                            "tags": tags_dict,
                            "metrics": f"No CloudWatch data returned over the last {TIME_FRAME} days",
                            "threshold_crossed": (
                                f"CPU < {config.CPU_THRESHOLD_PERCENT}% or "
                                f"Network < {config.NETWORK_THRESHOLD_BYTES / 1048576:.0f} MB, "
                                f"over {TIME_FRAME} days"),
                            "instance_type": instance_info.get('InstanceType'),
                        })
                        info_candidates.append((instance_id, instance_age, region, creator,
                                                "No Values Returned", "No Values Returned", "No Values Returned", "stale"))
                else:
                    info_candidates.append((instance_id, instance_age, region, creator,
                                            f"Resource Age less than {TIME_FRAME} days",
                                            f"Resource Age less than {TIME_FRAME} days",
                                            f"Resource Age less than {TIME_FRAME} days", "None"))

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
            TopicArn=config.SNS_TOPIC_ARN,
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
                    dynamodb.put_item(
                        TableName=table_name,
                        Item={
                            'Creator': {'S': creator},
                            'ResourceID': {'S': resource["resource_id"]},
                            'Type': {'S': resource["resource_type"]},
                            'Region': {'S': resource["region"]},
                            'Deletion_Status': {'S': "Marked"},
                            'Identification_Time': {'S': datetime.utcnow().strftime("%d-%m-%Y, %H:%M:%S")},
                            'Tags': {'M': {k: {'S': v} for k, v in resource["tags"].items()}},
                            'Metrics': {'S': resource["metrics"]},
                            'ThresholdCrossed': {'S': resource["threshold_crossed"]},
                            'InstanceType': {'S': resource["instance_type"] or ""},
                        }
                    )
                    logger.info(f"Stored stale EC2 {resource['resource_id']} in DynamoDB")
                except ClientError as e:
                    logger.exception(f"Error storing EC2 in DynamoDB: {e}")

                BODY_TEXT += (f"\n--> EC2 instance: {resource['resource_id']}, Owner: {creator} Region: {resource['region']}"
                              "\n identified as a stale resource"
                              "\n Delete it if not needed."
                              "\n If still needed, tag it with: Key='Stale', Value='false'")

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
