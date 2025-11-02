import os
import sys
import json
import logging
from datetime import datetime, timedelta
from schema import import_schema
import boto3
from botocore.exceptions import ClientError

# Logging
logger = logging.getLogger()
if len(logging.getLogger().handlers) > 0:
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s: %(levelname)s: %(message)s')

spacer = "_"*100
TIME_FRAME = 7
PERIOD = 86400 * TIME_FRAME
default_region = os.getenv("AWS_REGION", "us-east-1")

# DynamoDB client + ensure table

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

# Helper: identify creator via CloudTrail if no tag found

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
            user_identity = json.loads(event['CloudTrailEvent'])['userIdentity']
            if user_identity.get('type') == 'AssumedRole':
                creator_user = event["Username"]
                return creator_user
    return None
