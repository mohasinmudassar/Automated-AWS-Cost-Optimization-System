"""
Opens a pull request against a target Terraform repo proposing removal
or resizing of a flagged resource, instead of deleting it directly.
See README's "Why a pull request, not a delete" section (draft, 5.6).

This module is deployed as its own Lambda (see terraform/main.tf) with
its own IAM role and its own GITHUB_TOKEN — the ec2/lb/nat_gw auditor
Lambdas never see that token, and never gain the AWS permissions this
one needs. main_handler() is the Lambda entry point: it scans DynamoDB
for findings whose grace period (config.DELETION_DELAY_MINUTES) has
elapsed and, per config.REMEDIATION_MODE, either opens a PR (default,
"pr") or deletes the resource directly ("delete" — a separate,
explicit opt-in; Terraform only grants delete permissions to this
Lambda's role when that mode is actually selected).

Finding record shape (built from the DynamoDB item by
_finding_from_dynamodb_item(), or by hand for direct remediate() calls):
    {
        "resource_id": "i-0abc123",
        "resource_type": "EC2" | "LB" | "NAT_GW",
        "region": "ap-southeast-1",
        "owner": "alice@example.com",
        "tags": {"Name": "web-1", "owner": "alice@example.com", "team": "platform"},
        "metrics": "CPU 2.1%, NetworkIn 1.2 MB/day, NetworkOut 0.8 MB/day",
        "threshold_crossed": "CPU < 10% and Network < 5 MB/day over 7 days",
        "action": "remove" | "resize",
        "instance_type": "t3.micro",              # EC2 only
        "recommended_instance_type": "t3.micro",   # required when action == "resize"
    }

KNOWN LIMITATION, read before relying on this: locating the resource in
the target repo is a best-effort TAG match, not a resource-ID match.
The AWS resource ID (e.g. "i-0abc123") is assigned at apply time and
normally only exists in Terraform *state* — it essentially never
appears in .tf source, so searching for it there finds nothing in the
common case. Tags, on the other hand, are usually written literally in
the .tf source's `tags = { ... }` block and are also what the scan
Lambdas capture into the finding record, so they're the reliable join
available without touching state. This module requires ALL of the
finding's tags to match a resource block's own `tags = { ... }`
sub-block, inside a single .tf file, or it raises RemediationError
rather than guess — no match, an ambiguous (multiple) match, or a
resource with no tags block at all are all treated as "can't safely
edit this."

The robust fix is reading the target repo's actual Terraform state
(resource address -> real AWS ID, no ambiguity), but that needs backend
access (S3/remote state, plus whatever credentials the backend requires)
which is deliberately out of scope for this phase — this whole project
tries to run without AWS credentials wherever it can. Revisit this if/
when state access becomes available.

SAFETY RE-CHECK, AND ITS OWN LIMITATION: a finding sits in DynamoDB for
the whole grace period (config.DELETION_DELAY_MINUTES, ~7 days by
default) before this Lambda ever looks at it, so acting purely on that
stored data risks acting on a resource whose situation has since
changed. Before doing anything to a finding, main_handler() re-fetches
the resource's *current* tags and skips it (marking it "Excluded"
instead of remediating) if the owner has since tagged it stale=false —
covering the case of an owner opting out mid-grace-period. It does NOT
re-run the CloudWatch/threshold check the original scan did, so a
resource that quietly became busy again without anyone re-tagging it
still gets remediated on the week-old finding — a deliberate scope cut
(re-evaluating metrics here means duplicating each auditor's
metric/threshold logic for all three resource types), not an oversight.
"""
import base64
import logging
import re
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError
import requests

import config
import pricing

logger = logging.getLogger()
if len(logging.getLogger().handlers) > 0:
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s: %(levelname)s: %(message)s')

dynamodb = boto3.client('dynamodb', region_name=config.AWS_REGION)

GITHUB_API = "https://api.github.com"

_RESOURCE_BLOCK_RE = re.compile(r'^\s*resource\s+"[^"]+"\s+"[^"]+"\s*{')
_TAGS_BLOCK_RE = re.compile(r'^\s*tags\s*=\s*{')
_TAG_LINE_RE = re.compile(r'^\s*"?([\w.-]+)"?\s*=\s*"([^"]*)"\s*$')
_INSTANCE_TYPE_RE = re.compile(r'^(\s*instance_type\s*=\s*")[^"]+(".*)$')


class RemediationError(Exception):
    pass


def _headers():
    return {
        "Authorization": f"Bearer {config.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _list_terraform_files(owner, repo, ref):
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{ref}",
        headers=_headers(), params={"recursive": "1"}, timeout=30,
    )
    resp.raise_for_status()
    return [
        item["path"] for item in resp.json()["tree"]
        if item["type"] == "blob" and item["path"].endswith(".tf")
    ]


def _get_file_content(owner, repo, path, ref):
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
        headers=_headers(), params={"ref": ref}, timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return content, data["sha"]


def _find_tags_block(lines, start, end):
    for i in range(start, end + 1):
        if not _TAGS_BLOCK_RE.match(lines[i]):
            continue
        depth = 0
        tag_start = i
        for j in range(i, end + 1):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0:
                tags = {}
                for k in range(tag_start + 1, j):
                    m = _TAG_LINE_RE.match(lines[k])
                    if m:
                        tags[m.group(1)] = m.group(2)
                return tags
        return None
    return None


def _resource_blocks(lines):
    i = 0
    while i < len(lines):
        if _RESOURCE_BLOCK_RE.match(lines[i]):
            depth = 0
            for j in range(i, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth == 0:
                    yield (i, j)
                    i = j
                    break
        i += 1


def locate_resource(owner, repo, ref, tags):
    if not tags:
        raise RemediationError(
            "No tags on this finding — nothing reliable to match against "
            f"in {owner}/{repo} (see this module's docstring: resource IDs "
            "generally aren't in .tf source, only in state).")

    matches = []
    any_resource_had_a_tags_block = False

    for path in _list_terraform_files(owner, repo, ref):
        content, sha = _get_file_content(owner, repo, path, ref)
        lines = content.splitlines()
        for start, end in _resource_blocks(lines):
            block_tags = _find_tags_block(lines, start, end)
            if block_tags is None:
                continue
            any_resource_had_a_tags_block = True
            if all(block_tags.get(k) == v for k, v in tags.items()):
                matches.append((path, start, end, lines, sha))

    if not matches:
        if any_resource_had_a_tags_block:
            raise RemediationError(
                f"No resource block in {owner}/{repo} has tags matching "
                f"{tags!r} — either it's not there, or its tags in .tf "
                "source have drifted from what AWS actually has.")
        raise RemediationError(
            f"No resource block with a tags = {{ ... }} block found "
            f"anywhere in {owner}/{repo} — nothing to match against.")
    if len(matches) > 1:
        raise RemediationError(
            f"Tags {tags!r} matched {len(matches)} resource blocks in "
            f"{owner}/{repo} — too ambiguous to edit automatically.")
    return matches[0]


def _remove_block(lines, start, end):
    new_lines = lines[:start] + lines[end + 1:]
    if (start < len(new_lines) and new_lines[start] == ""
            and start > 0 and new_lines[start - 1] == ""):
        del new_lines[start]
    return "\n".join(new_lines) + "\n"


def _resize_block(lines, start, end, new_instance_type):
    new_lines = list(lines)
    for i in range(start, end + 1):
        m = _INSTANCE_TYPE_RE.match(new_lines[i])
        if m:
            new_lines[i] = f"{m.group(1)}{new_instance_type}{m.group(2)}"
            return "\n".join(new_lines) + "\n"
    raise RemediationError(
        "No instance_type attribute found in the matched resource block — can't resize.")


def _build_pr_body(finding, estimated_monthly_cost_usd):
    if estimated_monthly_cost_usd is not None:
        cost_line = (
            f"~${estimated_monthly_cost_usd:.2f}/month (on-demand list price, "
            "base hourly rate only — excludes data-processing/LCU charges, "
            "see functions/remediation/pricing.py for sources)"
        )
    else:
        cost_line = "Not available (no listed rate for this resource/instance type)."

    return (
        f"## Stale resource: `{finding['resource_id']}` ({finding['resource_type']})\n\n"
        f"**Region:** {finding['region']}\n"
        f"**Owner:** {finding['owner']}\n"
        f"**Matched by tags:** {finding['tags']}\n\n"
        f"### Evidence\n{finding['metrics']}\n\n"
        f"### Threshold crossed\n{finding['threshold_crossed']}\n\n"
        f"### Estimated cost\n{cost_line}\n\n"
        "### Still need this resource?\n"
        "Tag it `stale=false` in AWS — the next scan will exclude it, "
        "and you can close this PR without merging.\n"
    )


def remediate(finding: dict) -> dict:
    owner, repo = config.TARGET_REPO.split("/", 1)
    action = finding["action"]

    path, start, end, lines, file_sha = locate_resource(
        owner, repo, config.BASE_BRANCH, finding["tags"])

    if action == "remove":
        new_content = _remove_block(lines, start, end)
        commit_verb = "Remove"
    elif action == "resize":
        new_content = _resize_block(
            lines, start, end, finding["recommended_instance_type"])
        commit_verb = "Resize"
    else:
        raise RemediationError(f"Unknown action: {action!r}")

    branch = f"{config.BRANCH_PREFIX}/{finding['resource_type'].lower()}-{finding['resource_id']}"

    base_ref = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{config.BASE_BRANCH}",
        headers=_headers(), timeout=30,
    )
    base_ref.raise_for_status()
    base_sha = base_ref.json()["object"]["sha"]

    create_ref = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
        headers=_headers(), timeout=30,
        json={"ref": f"refs/heads/{branch}", "sha": base_sha},
    )
    create_ref.raise_for_status()

    commit_message = f"{commit_verb} idle {finding['resource_type']} {finding['resource_id']}"
    update_file = requests.put(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
        headers=_headers(), timeout=30,
        json={
            "message": commit_message,
            "content": base64.b64encode(new_content.encode("utf-8")).decode("ascii"),
            "sha": file_sha,
            "branch": branch,
        },
    )
    update_file.raise_for_status()

    cost = pricing.estimate_monthly_cost_usd(
        finding["resource_type"], finding.get("instance_type"))

    pr_resp = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
        headers=_headers(), timeout=30,
        json={
            "title": f"{commit_verb} idle {finding['resource_type']} {finding['resource_id']}",
            "head": branch,
            "base": config.BASE_BRANCH,
            "body": _build_pr_body(finding, cost),
        },
    )
    pr_resp.raise_for_status()
    pr_data = pr_resp.json()

    return {"pr_url": pr_data["html_url"], "branch": branch}


def _grace_period_elapsed(item):
    identification_time = item.get('Identification_Time', {}).get('S')
    if not identification_time:
        return False
    identified_at = datetime.strptime(
        identification_time, "%d-%m-%Y, %H:%M:%S")
    return datetime.utcnow() >= identified_at + \
        timedelta(minutes=config.DELETION_DELAY_MINUTES)


def _pending_findings():
    paginator = dynamodb.get_paginator('scan')
    for page in paginator.paginate(TableName=config.TABLE_NAME):
        for item in page['Items']:
            if item.get('Deletion_Status', {}).get('S') != 'Marked':
                continue
            if not _grace_period_elapsed(item):
                continue
            yield item


def _finding_from_dynamodb_item(item):
    def s(key, default=None):
        return item.get(key, {}).get('S', default)

    tags = {k: v['S'] for k, v in item.get('Tags', {}).get('M', {}).items()}

    finding = {
        "resource_id": s('ResourceID'),
        "resource_type": s('Type'),
        "region": s('Region'),
        "owner": s('Creator'),
        "tags": tags,
        "metrics": s('Metrics', ''),
        "threshold_crossed": s('ThresholdCrossed', ''),
        "action": "remove",
    }
    if finding["resource_type"] == "EC2":
        finding["instance_type"] = s('InstanceType')
    if finding["resource_type"] == "LB":
        finding["resource_arn"] = s('ResourceArn')
    return finding


def _mark_remediated(item, status, detail=None):
    update_expr = "SET Deletion_Status = :s"
    values = {':s': {'S': status}}
    if detail:
        update_expr += ", RemediationResult = :d"
        values[':d'] = {'S': detail}
    dynamodb.update_item(
        TableName=config.TABLE_NAME,
        Key={'ResourceID': item['ResourceID'], 'Type': item['Type']},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
    )


def _owner_opted_out_since_detection(finding):
    region = finding["region"]
    resource_type = finding["resource_type"]
    resource_id = finding["resource_id"]

    try:
        if resource_type in ("EC2", "NAT_GW"):
            tags = boto3.client('ec2', region_name=region).describe_tags(
                Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])['Tags']
            tag_dict = {t['Key']: t['Value'] for t in tags}
        elif resource_type == "LB":
            arn = finding.get("resource_arn")
            if not arn:
                logger.info(
                    f"No ResourceArn stored for LB {resource_id!r} — can't "
                    "re-check its current tags before acting; proceeding "
                    "on the finding's original data.")
                return False
            tag_descriptions = boto3.client('elbv2', region_name=region).describe_tags(
                ResourceArns=[arn])['TagDescriptions']
            tag_dict = {t['Key']: t['Value'] for t in tag_descriptions[0]['Tags']}
        else:
            return False
    except ClientError as e:
        logger.info(
            f"Could not re-check current tags for {resource_id} before "
            f"acting ({e}) — proceeding on the finding's original data "
            "rather than blocking remediation on a transient API error.")
        return False

    return tag_dict.get('stale') == 'false'


def _delete_resource(finding):
    region = finding["region"]
    resource_type = finding["resource_type"]
    resource_id = finding["resource_id"]

    if resource_type == "EC2":
        boto3.client('ec2', region_name=region).terminate_instances(
            InstanceIds=[resource_id])
    elif resource_type == "NAT_GW":
        boto3.client('ec2', region_name=region).delete_nat_gateway(
            NatGatewayId=resource_id)
    elif resource_type == "LB":
        arn = finding.get("resource_arn")
        if not arn:
            raise RemediationError(
                f"No ResourceArn stored for LB {resource_id!r} — can't "
                "delete a load balancer without its full ARN.")
        boto3.client('elbv2', region_name=region).delete_load_balancer(
            LoadBalancerArn=arn)
    else:
        raise RemediationError(f"Unknown resource_type: {resource_type!r}")


def main_handler(event, context):
    processed = 0
    for item in _pending_findings():
        finding = _finding_from_dynamodb_item(item)
        try:
            if _owner_opted_out_since_detection(finding):
                _mark_remediated(
                    item, "Excluded",
                    detail="Owner tagged stale=false after detection but "
                           "before the grace period elapsed.")
                logger.info(
                    f"Skipping {finding['resource_type']} {finding['resource_id']}: "
                    "opted out since detection")
                continue

            if config.REMEDIATION_MODE == "delete":
                _delete_resource(finding)
                _mark_remediated(item, "Deleted")
                logger.info(
                    f"Deleted {finding['resource_type']} {finding['resource_id']}")
            else:
                result = remediate(finding)
                _mark_remediated(item, "PR_Opened", detail=result["pr_url"])
                logger.info(
                    f"Opened {result['pr_url']} for {finding['resource_type']} "
                    f"{finding['resource_id']}")
            processed += 1
        except RemediationError as e:
            logger.exception(
                f"Could not remediate {finding['resource_id']}: {e}")
        except Exception as e:
            logger.exception(
                f"Unexpected error remediating {finding['resource_id']}: {e}")

    return {"processed": processed}
