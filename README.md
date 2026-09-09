# 🧭 Automated AWS Cost Optimization System (EC2 / LB / NAT Gateway)

> A governance workflow for idle AWS resources, not another idle-resource detector.

---

## 🧩 Overview

Detecting idle resources is a solved problem. AWS Compute Optimizer has
shipped idle-resource detection natively since November 2024, and most
cost tools do some version of "flag anything with low CPU." That part is
commodity — this project isn't trying to out-detect it.

What detection alone doesn't do is close the loop: figure out **who**
owns a flagged resource, **tell them directly**, give them a **grace
period** to justify or reclaim it, and only then turn the finding into a
**reviewable change** instead of a silent deletion. That loop — not the
detection step — is what this system is built around, applied
consistently across **EC2 instances**, **Load Balancers**, and **NAT
Gateways**:

- Resolves ownership from resource tags, falling back to **CloudTrail**
  when no tag is present
- Notifies the owner directly via **SES**
- Records every finding in **DynamoDB** so nothing is only ever an email
- Publishes a summary to **SNS** for the ops/FinOps team
- Applies a grace period before any remediation is taken, using
  **CloudWatch metrics** to decide what's actually idle in the first
  place

---

## ⚙️ Key Features

- 🔍 **Multi-Region Scanning** for EC2, LB, and NAT GW  
- 📊 **CloudWatch Metrics Analysis** via `GetMetricData`  
- ⚡ **Idle Detection** using CPU %, Network I/O, and connection thresholds  
- 🧾 **Ownership Resolution** via `creator` tag or CloudTrail logs  
- 🗃️ **Data Persistence** in DynamoDB  
- 📧 **SES Alerts** for owners + **SNS Summaries** for ops teams  
- ⏰ **Optional Auto-Delete Scheduling** through EventBridge rules  
- 🧱 **Lambda Layers** for reusable schema + dependencies  

---

## 🏗️ Architecture Overview

Below is the system’s AWS architecture showing how the components interact end-to-end:

![AWS Idle Resource Auditor Architecture](Architecture_Diagram.png)

## 🧱 Core Components

| Component | Description |
|------------|--------------|
| **EC2 Auditor Lambda** | Scans EC2 instances; checks CPU and network activity. |
| **LB Auditor Lambda** | Monitors ALB/NLB/CLB/GLB; detects inactive load balancers. |
| **NAT GW Auditor Lambda** | Detects idle NAT Gateways using connection metrics. |
| **DynamoDB** | Stores detected stale resource metadata. |
| **SNS** | Sends summaries to Ops / FinOps team. |
| **SES** | Notifies resource owners directly. |
| **EventBridge** | Triggers the daily scan — and, on the same schedule, remediation's own check for findings past their grace period. |
| **Remediation Lambda** | Reads findings from DynamoDB once their grace period has elapsed; opens a pull request by default, or deletes the resource directly in the separate, explicitly opt-in "delete" mode. |
| **Lambda Layers** | Provide shared schema + dependency packages. |

---

## 📊 Metric Definitions

Metrics tracked for each resource type, with statistics and units:

| Resource | Metrics | Stat | Unit |
|-----------|----------|------|------|
| **EC2** | NetworkIn, NetworkOut, CPUUtilization | Sum / Average | Bytes / Percent |
| **NAT GW** | ConnectionAttemptCount | Sum | Count |
| **LB** | RequestCount | Sum | Count |

---

## 🧠 Idle Detection Logic

| Resource | Metric | Idle Criteria | Thresholds |
|-----------|---------|----------------|-------------|
| **EC2** | CPUUtilization + NetworkIn/Out | CPU < 10% and Network < 5 MB/day | 10% / 5 MB |
| **LB** | RequestCount | < 1000 requests in 7 days | 1000 req/week |
| **NAT GW** | ConnectionAttemptCount | < 7 connection attempts in 7 days | 7 attempts |

---

## 🔄 Workflow Summary

### 1️⃣ **Discovery & Ownership**
- Enumerates EC2, LB, and NAT Gateways via AWS APIs.
- Resolves `creator` tag or infers from CloudTrail events.

### 2️⃣ **Metrics Collection**
- Fetches resource metrics from CloudWatch using schema definitions.

### 3️⃣ **Idle Evaluation**
- Applies thresholds to determine if a resource is idle.

### 4️⃣ **Storage & Notification**
- Writes details into DynamoDB.
- Sends SES email to the resource owner.
- Publishes a summary message via SNS.

### 5️⃣ **Remediation, After a Grace Period**
- A separate remediation Lambda runs on the same schedule as the scans.
- For every finding whose grace period has elapsed, it opens a pull
  request by default (see below) — or, only if explicitly configured
  into "delete" mode, deletes the resource directly.

---

## ✅ Tests

Each detector has three cases: an idle resource that's flagged, a busy
one that isn't, and one explicitly excluded via a `stale=false` tag —
that last case matters most, since a cleanup tool that flags something
still in active use is the failure that erodes trust fastest.

---

## 🔀 Why a Pull Request, Not a Delete

> **Draft — I'm rewriting this section in my own words.**

By default, remediation doesn't touch AWS at all. Once a finding's
grace period has elapsed, it opens a pull request against your
infrastructure repo proposing the change (remove the resource, or
resize it) — the same way any other infrastructure change gets made:
reviewed, in the open, by a person who can say no.

The pull request carries the resource ID and type, the CloudWatch
evidence that got it flagged, the threshold it crossed, a rough
estimated monthly cost, and a reminder that tagging the resource
`stale=false` in AWS excludes it from the next scan and makes the PR
safe to close unmerged. Nothing about this requires trusting the tool's
detection to be perfect — the worst case of a wrong PR is a wrong PR,
not a production outage with no human in the loop.

A "delete" mode exists (`remediation_mode = "delete"` in Terraform) for
teams that want the old fully-autonomous behavior. It's a deliberate,
separate opt-in, not the default — Terraform only grants the
remediation Lambda's IAM role the actual delete permissions
(`ec2:TerminateInstances`, `ec2:DeleteNatGateway`,
`elasticloadbalancing:DeleteLoadBalancer`) when that mode is switched
on, so a "pr"-mode deployment's role physically cannot delete anything,
regardless of what any Lambda environment variable says.

### Safety re-check before acting, and its own limitation

A finding sits in DynamoDB for the whole grace period (about a week by
default) before remediation ever looks at it again, so acting purely
on that stored data risks acting on a resource whose situation has
changed since. Immediately before opening a PR or deleting anything,
remediation re-fetches the resource's **current** tags and skips it —
marking it "Excluded" rather than remediating — if the owner has since
tagged it `stale=false`. That covers an owner opting out mid-grace-period.

It does **not** re-run the CloudWatch/threshold check the original scan
did. A resource that quietly became busy again without anyone
re-tagging it still gets remediated on the week-old finding. Re-checking
metrics too would close that gap fully, at the cost of duplicating each
scan Lambda's metric/threshold logic inside remediation for all three
resource types — a deliberate scope cut for now, not an oversight.

### Known limitation: matching is tag-based, not state-based

Opening a PR means finding the right block in your `.tf` source to
edit. The AWS resource ID (`i-0abc123`) is assigned when Terraform
applies and is normally only recorded in **state** — it essentially
never appears in the source itself, so searching for it there finds
nothing in the common case. Tags, on the other hand, are usually
written literally in a resource's `tags = { ... }` block, and they're
also what the scan Lambdas already capture into each finding. So
remediation matches on tags: it requires every tag on the finding to
match a resource block's own tags, in exactly one place in the repo, or
it refuses to act rather than guess. No match, more than one match, or
a resource with no tags block at all are all treated the same way — as
"I can't safely edit this."

The robust fix is reading the target repo's actual Terraform state —
the authoritative resource-address-to-real-AWS-ID mapping, no
ambiguity. That needs backend access (credentials for wherever that
repo's state lives), which this project deliberately avoids needing
anywhere else, so it's out of scope for now rather than quietly assumed
away. If your infrastructure repo's resources aren't consistently
tagged, or its tags in `.tf` source have drifted from what's actually
running in AWS, this won't find them — that's a real gap, not a
theoretical one, and worth knowing before relying on this for real
infrastructure.

---

## 🪜 Deployment

Everything above — the Lambdas, layer, DynamoDB table, SNS/SES, and the
scan schedule — is provisioned by Terraform, in `terraform/`.

1. Create the Terraform state bucket once, outside this config
   (versioned, encrypted — see `terraform/backend.tf`).
2. Copy `terraform/backend.hcl.example` → `backend.hcl` and
   `terraform/terraform.tfvars.example` → `terraform.tfvars`, filling in
   your own values.
3. From `terraform/`:
   ```bash
   terraform init -backend-config=backend.hcl
   terraform apply
   ```

---

## 🏁 Summary

The **AWS Idle Resource Auditor** provides a fully automated, serverless framework for identifying, notifying, and cleaning up unused AWS resources.  
It combines **CloudWatch**, **DynamoDB**, **SNS/SES**, and **EventBridge** to promote cost efficiency and better cloud hygiene.

