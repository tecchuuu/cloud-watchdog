"""
scanner.py — Cloud Watchdog scanner.

Finds wasted money and security risks in the AWS account.
Each check is one function: check_<name>(region) -> list of findings.
Adding a new check = writing one more function and adding it to CHECKS.

Right now this runs by hand in CloudShell:
    python3 lambda/scanner.py
Saving to DynamoDB / S3 and emailing come in a later step.

Checks: 1 unused Elastic IP, 2 admin ports open to the world, 3 public S3 bucket,
        4 unattached EBS volume, 5 idle EC2 instance.
"""

import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------- settings

REGIONS = os.environ.get("REGIONS", "us-east-1,us-west-2").split(",")

HOURS_PER_MONTH = 730
EIP_HOURLY_USD = 0.005          # public IPv4 address, per hour
MEDIUM_COST_USD = 20            # a cost finding this big becomes MEDIUM

IDLE_CPU_PERCENT = float(os.environ.get("IDLE_CPU_PERCENT", "5"))
IDLE_HOURS = int(os.environ.get("IDLE_HOURS", "24"))

# EBS price per GB per month, us-east-1
EBS_USD_PER_GB = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125,
                  "st1": 0.045, "sc1": 0.015, "standard": 0.05}

# EC2 on-demand price per hour, us-east-1 (unknown type = no estimate)
EC2_USD_PER_HOUR = {"t2.micro": 0.0116, "t3.micro": 0.0104, "t2.small": 0.023,
                    "t3.small": 0.0208, "t3.medium": 0.0416}

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL"}
WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"
ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


# ----------------------------------------------------------------- helpers

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tag_dict(tag_list):
    """AWS returns tags as [{'Key': k, 'Value': v}, ...]; turn that into {k: v}."""
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def is_protected(tags):
    """Resources the Watchdog must never report or touch."""
    return (tags.get("managed-by") == "watchdog"          # the app's own resources
            or tags.get("watchdog-ignore") == "true")     # user pressed Ignore


def make_finding(check, category, severity, region, resource_id, resource_name,
                 detail, est_monthly_usd=None, cis=None):
    """Build one finding in the shape the rest of the app expects."""
    if est_monthly_usd is not None and est_monthly_usd >= MEDIUM_COST_USD and severity == "LOW":
        severity = "MEDIUM"
    return {
        "finding_id": f"{check}#{region}#{resource_id}",
        "check": check,
        "category": category,          # "cost" or "security"
        "severity": severity,          # HIGH, MEDIUM, LOW
        "region": region,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "detail": detail,
        "est_monthly_usd": est_monthly_usd,
        "cis": cis,
        "last_seen": now_iso(),
    }


# ------------------------------------------------------------------ checks

def check_unused_eip(region):
    """#1 Elastic IPs that are not attached to anything still cost money."""
    ec2 = boto3.client("ec2", region_name=region)
    findings = []
    for addr in ec2.describe_addresses()["Addresses"]:
        tags = tag_dict(addr.get("Tags"))
        if is_protected(tags) or "AssociationId" in addr:
            continue   # protected, or attached to something = in use
        findings.append(make_finding(
            check="unused_eip", category="cost", severity="LOW",
            region=region,
            resource_id=addr["AllocationId"],
            resource_name=tags.get("Name", addr["PublicIp"]),
            detail=f"Elastic IP {addr['PublicIp']} is not attached to anything",
            est_monthly_usd=round(EIP_HOURLY_USD * HOURS_PER_MONTH, 2),
        ))
    return findings


def _open_admin_ports(permission):
    """Which admin ports does this one inbound rule open to the whole internet?
    Returns (list of port names, opened_on_ipv6)."""
    world_v4 = any(r.get("CidrIp") == WORLD_IPV4 for r in permission.get("IpRanges", []))
    world_v6 = any(r.get("CidrIpv6") == WORLD_IPV6 for r in permission.get("Ipv6Ranges", []))
    if not (world_v4 or world_v6):
        return [], False

    protocol = permission["IpProtocol"]
    if protocol == "-1":                       # "all traffic" covers every port
        return list(ADMIN_PORTS.values()), world_v6
    if protocol not in ("tcp", "6"):
        return [], False

    low, high = permission["FromPort"], permission["ToPort"]
    opened = [name for port, name in ADMIN_PORTS.items() if low <= port <= high]
    return opened, world_v6


def check_open_admin_ports(region):
    """#2 Security groups that let anyone on the internet reach SSH / RDP / MySQL."""
    ec2 = boto3.client("ec2", region_name=region)

    # Learner Lab's default VPC and its "default" group are off limits.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    default_vpc_id = default_vpcs[0]["VpcId"] if default_vpcs else None

    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            tags = tag_dict(sg.get("Tags"))
            if is_protected(tags):
                continue
            if sg["GroupName"] == "default" and sg.get("VpcId") == default_vpc_id:
                continue

            open_ports, on_ipv6 = set(), False
            for perm in sg.get("IpPermissions", []):
                ports, v6 = _open_admin_ports(perm)
                open_ports.update(ports)
                on_ipv6 = on_ipv6 or (v6 and bool(ports))
            if not open_ports:
                continue

            port_list = ", ".join(sorted(open_ports))
            # CIS AWS Foundations v3.0: 5.2 = IPv4, 5.3 = IPv6 (TODO: confirm numbers)
            findings.append(make_finding(
                check="open_admin_ports", category="security", severity="HIGH",
                region=region,
                resource_id=sg["GroupId"],
                resource_name=sg["GroupName"],
                detail=f"Security group lets anyone on the internet reach {port_list}",
                cis="CIS 5.3" if on_ipv6 else "CIS 5.2",
            ))
    return findings


def _bucket_region(s3, bucket):
    """Buckets in us-east-1 report their location as None."""
    location = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return location or "us-east-1"


def _bucket_tags(s3, bucket):
    try:
        return tag_dict(s3.get_bucket_tagging(Bucket=bucket)["TagSet"])
    except ClientError:          # NoSuchTagSet = bucket has no tags
        return {}


def _bucket_block_settings(s3, bucket):
    """The bucket's own Block Public Access switches (all False if never set)."""
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError:          # NoSuchPublicAccessBlockConfiguration
        return {}


def _policy_is_public(s3, bucket):
    try:
        return s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
    except ClientError:          # NoSuchBucketPolicy = no policy at all
        return False


def _acl_is_public(s3, bucket):
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return any(g["Grantee"].get("URI") == ALL_USERS_URI for g in grants)


def _is_website(s3, bucket):
    try:
        s3.get_bucket_website(Bucket=bucket)
        return True
    except ClientError:          # NoSuchWebsiteConfiguration
        return False


def check_public_bucket():
    """#3 S3 buckets anyone on the internet can read.
    S3 is global, so this runs once, not once per region."""
    findings = []
    for b in boto3.client("s3").list_buckets()["Buckets"]:
        name = b["Name"]
        region = _bucket_region(boto3.client("s3"), name)
        s3 = boto3.client("s3", region_name=region)   # talk to the bucket's own region

        if is_protected(_bucket_tags(s3, name)):
            continue

        block = _bucket_block_settings(s3, name)
        public_by_policy = _policy_is_public(s3, name) and not block.get("RestrictPublicBuckets")
        public_by_acl = _acl_is_public(s3, name) and not block.get("IgnorePublicAcls")
        if not (public_by_policy or public_by_acl):
            continue

        how = "bucket policy" if public_by_policy else "ACL"
        if _is_website(s3, name):
            severity = "MEDIUM"
            detail = f"Bucket is public via its {how}. It hosts a website; Ignore if that's intended"
        else:
            severity = "HIGH"
            detail = f"Bucket is public: anyone can read it via its {how}"

        findings.append(make_finding(
            check="public_bucket", category="security", severity=severity,
            region=region, resource_id=name, resource_name=name,
            detail=detail,
            cis="CIS 2.1.4",   # TODO: confirm against CIS AWS Foundations v3.0
        ))
    return findings


def check_unattached_ebs(region):
    """#4 EBS volumes not attached to any instance still cost money per GB."""
    ec2 = boto3.client("ec2", region_name=region)
    findings = []
    pages = ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "status", "Values": ["available"]}])   # available = not attached
    for page in pages:
        for vol in page["Volumes"]:
            tags = tag_dict(vol.get("Tags"))
            if is_protected(tags):
                continue
            price = EBS_USD_PER_GB.get(vol["VolumeType"])
            cost = round(vol["Size"] * price, 2) if price else None
            findings.append(make_finding(
                check="unattached_ebs", category="cost", severity="LOW",
                region=region,
                resource_id=vol["VolumeId"],
                resource_name=tags.get("Name", vol["VolumeId"]),
                detail=f"{vol['Size']} GiB {vol['VolumeType']} volume is not attached to any instance",
                est_monthly_usd=cost,
            ))
    return findings


def _hourly_cpu(cloudwatch, instance_id):
    """Average CPU % for each hour of the last IDLE_HOURS hours."""
    end = datetime.now(timezone.utc)
    stats = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=end - timedelta(hours=IDLE_HOURS),
        EndTime=end,
        Period=3600,                 # one data point per hour
        Statistics=["Average"],
    )
    return [p["Average"] for p in stats["Datapoints"]]


def check_idle_ec2(region):
    """#5 Running instances whose CPU stayed under IDLE_CPU_PERCENT every hour."""
    ec2 = boto3.client("ec2", region_name=region)
    cloudwatch = boto3.client("cloudwatch", region_name=region)
    findings = []
    pages = ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                tags = tag_dict(inst.get("Tags"))
                if is_protected(tags):
                    continue
                cpu = _hourly_cpu(cloudwatch, inst["InstanceId"])
                if not cpu:
                    continue          # no CPU data yet: too new to judge
                if max(cpu) >= IDLE_CPU_PERCENT:
                    continue          # busy at least once: not idle

                itype = inst["InstanceType"]
                hourly = EC2_USD_PER_HOUR.get(itype)
                findings.append(make_finding(
                    check="idle_ec2", category="cost", severity="LOW",
                    region=region,
                    resource_id=inst["InstanceId"],
                    resource_name=tags.get("Name", inst["InstanceId"]),
                    detail=(f"{itype} has been under {IDLE_CPU_PERCENT:g}% CPU for "
                            f"{len(cpu)} h (peak {max(cpu):.1f}%)"),
                    est_monthly_usd=round(hourly * HOURS_PER_MONTH, 2) if hourly else None,
                ))
    return findings


# Per-region checks run once for each region in REGIONS; global ones run once.
REGIONAL_CHECKS = [check_unused_eip, check_open_admin_ports,
                   check_unattached_ebs, check_idle_ec2]
GLOBAL_CHECKS = [check_public_bucket]


# -------------------------------------------------------------------- scan

def run_checks():
    """Run every check. One broken check is reported, not allowed to stop the scan."""
    findings, errors = [], []
    jobs = [(check, region) for check in REGIONAL_CHECKS for region in REGIONS]
    jobs += [(check, None) for check in GLOBAL_CHECKS]

    for check, region in jobs:
        try:
            findings += check(region) if region else check()
        except ClientError as e:
            errors.append(f"{check.__name__} ({region or 'global'}): {e}")
    return findings, errors


def print_report(findings, errors):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(findings, key=lambda f: (order[f["severity"]], f["check"]))

    print(f"{'SEVERITY':<8} {'CHECK':<17} {'REGION':<10} {'$/MONTH':>8}  {'CIS':<9} RESOURCE / DETAIL")
    for f in findings:
        cost = f"{f['est_monthly_usd']:.2f}" if f["est_monthly_usd"] is not None else "-"
        print(f"{f['severity']:<8} {f['check']:<17} {f['region']:<10} {cost:>8}  "
              f"{f['cis'] or '-':<9} {f['resource_name']}  ({f['resource_id']})")
        print(f"{'':<56}{f['detail']}")

    wasted = sum(f["est_monthly_usd"] or 0 for f in findings)
    print(f"\n{len(findings)} findings, about ${wasted:.2f}/month wasted")
    for e in errors:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    print_report(*run_checks())
