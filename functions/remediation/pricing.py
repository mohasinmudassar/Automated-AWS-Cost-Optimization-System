"""
AWS on-demand pricing constants, used only to put a rough estimated
monthly cost in remediation PR bodies (see 5.3). Deliberately not
fetched at runtime — a static, committed, auditable number beats a live
API call that can silently drift or fail mid-remediation, and every
figure here has its source and date recorded so it's obvious when to
re-check them.

Source:
  EC2:          https://aws.amazon.com/ec2/pricing/on-demand/
  NAT Gateway:  https://aws.amazon.com/vpc/pricing/
  ALB:          https://aws.amazon.com/elasticloadbalancing/pricing/
As of: 2026-09-08. Linux, on-demand, US East (N. Virginia). These are
list prices for the base hourly rate only — NAT Gateway data-processing
charges and ALB LCU charges are usage-dependent and can't be estimated
from a resource ID alone, so they're excluded rather than guessed.
Re-verify against AWS's own pricing pages before relying on these for
a real decision; AWS revises pricing without much notice, and actual
cost will differ by region, OS, and usage.
"""

HOURS_PER_MONTH = 730

EC2_HOURLY_USD = {
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "m5.large": 0.096,
}

NAT_GATEWAY_HOURLY_USD = 0.045
LOAD_BALANCER_HOURLY_USD = 0.0225


def estimate_monthly_cost_usd(resource_type, instance_type=None):
    if resource_type == "NAT_GW":
        return round(NAT_GATEWAY_HOURLY_USD * HOURS_PER_MONTH, 2)
    if resource_type == "LB":
        return round(LOAD_BALANCER_HOURLY_USD * HOURS_PER_MONTH, 2)
    if resource_type == "EC2":
        rate = EC2_HOURLY_USD.get(instance_type)
        return round(rate * HOURS_PER_MONTH, 2) if rate is not None else None
    return None
