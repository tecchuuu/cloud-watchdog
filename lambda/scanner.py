"""
scanner.py — Cloud Watchdog scanner.

Finds wasted money and security risks in the AWS account.
Each check is one function: check_<name>(region) -> list of findings.
Adding a new check = writing one more function and adding it to CHECKS.

After the checks, each scan is compared with the last one (NEW / OPEN / FIXED),
graded A–F, saved to DynamoDB, written to S3 as a JSON report, and NEW issues
are emailed through SNS.

Two ways to run it:
    on AWS:        Lambda calls lambda_handler() (daily via EventBridge, or Scan now)
    in CloudShell: python3 lambda/scanner.py
                   Without FINDINGS_TABLE etc. set, it only prints (nothing saved).

Checks: 1 unused Elastic IP, 2 admin ports open to the world, 3 public S3 bucket,
        4 unattached EBS volume, 5 idle EC2 instance.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------- settings

REGIONS = os.environ.get("REGIONS", "us-east-1,us-west-2").split(",")

# Set by OpenTofu on the Lambda. Missing (e.g. in CloudShell) = just print, save nothing.
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

REMINDER_DAYS = 7               # OPEN this long -> listed in the Monday reminder

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


# ------------------------------------------------------------------- grade

SEVERITY_POINTS = {"HIGH": 25, "MEDIUM": 10, "LOW": 5}


def grade(active_findings):
    """Start at 100, lose points per open finding. Returns (score, letter)."""
    lost = sum(SEVERITY_POINTS[f["severity"]] for f in active_findings)
    score = max(0, 100 - lost)
    for letter, minimum in (("A", 90), ("B", 80), ("C", 70), ("D", 60)):
        if score >= minimum:
            return score, letter
    return score, "F"


# ------------------------------------------------- state: NEW / OPEN / FIXED

def _to_dynamo(item):
    """DynamoDB won't take Python floats or empty values: floats -> Decimal, drop None."""
    return {k: Decimal(str(v)) if isinstance(v, float) else v
            for k, v in item.items() if v is not None}


def _from_dynamo(item):
    """And back: Decimal -> float, so the rest of the code sees plain numbers."""
    return {k: float(v) if isinstance(v, Decimal) else v for k, v in item.items()}


def load_previous(table):
    """Every finding saved by earlier scans, keyed by finding_id."""
    items, kwargs = [], {}
    while True:                                   # scan() returns 1 MB at a time
        page = table.scan(**kwargs)
        items += page["Items"]
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return {i["finding_id"]: _from_dynamo(i) for i in items}


def update_state(current, previous):
    """Compare this scan with the last one and give every finding its status."""
    now = now_iso()
    result = {}

    for f in current:
        old = previous.get(f["finding_id"])
        if old is None or old["status"] == "FIXED":
            f.update(status="NEW", first_seen=now)                # first time, or came back
        elif old["status"] == "IGNORED":
            f.update(status="IGNORED", first_seen=old.get("first_seen", now),
                     ignore_reason=old.get("ignore_reason"))      # stays ignored
        else:
            f.update(status="OPEN", first_seen=old.get("first_seen", now))   # still there
        result[f["finding_id"]] = f

    for finding_id, old in previous.items():
        if finding_id in result:
            continue
        if old["status"] in ("NEW", "OPEN"):
            old.update(status="FIXED", fixed_at=now)              # gone since last scan
        result[finding_id] = old                                  # keep FIXED/IGNORED history
    return list(result.values())


def save_findings(table, findings):
    with table.batch_writer() as batch:          # sends writes 25 at a time
        for f in findings:
            batch.put_item(Item=_to_dynamo(f))


# ---------------------------------------------------------- report + email

def build_summary(findings, errors, scanned_at):
    active = [f for f in findings if f["status"] in ("NEW", "OPEN")]
    fixed = [f for f in findings if f["status"] == "FIXED"]
    score, letter = grade(active)
    return {
        "scanned_at": scanned_at,
        "score": score,
        "grade": letter,
        "counts": {s: sum(f["severity"] == s for f in active) for s in ("HIGH", "MEDIUM", "LOW")},
        "new": sum(f["status"] == "NEW" for f in active),
        "open": sum(f["status"] == "OPEN" for f in active),
        "fixed_total": len(fixed),
        "wasted_usd": round(sum(f.get("est_monthly_usd") or 0 for f in active), 2),
        "saved_usd": round(sum(f.get("est_monthly_usd") or 0 for f in fixed), 2),
        "errors": errors,
    }


def save_report(summary, findings):
    """One JSON file per scan: reports/YYYY/MM/DD/<time>.json (the Report tab's history)."""
    t = datetime.strptime(summary["scanned_at"], "%Y-%m-%dT%H:%M:%SZ")
    key = f"reports/{t:%Y/%m/%d}/{t:%Y%m%dT%H%M%SZ}.json"
    active = [f for f in findings if f["status"] in ("NEW", "OPEN")]
    body = json.dumps({**summary, "findings": active}, indent=2)
    boto3.client("s3").put_object(Bucket=REPORTS_BUCKET, Key=key, Body=body,
                                  ContentType="application/json")
    return key


def _line(f):
    cost = f", ~${f['est_monthly_usd']:.2f}/month" if f.get("est_monthly_usd") else ""
    return f"- [{f['severity']}] {f['resource_name']} ({f['region']}): {f['detail']}{cost}"


def email_new(findings, summary):
    """Email only what's NEW, so the daily email doesn't nag about old things."""
    new = [f for f in findings if f["status"] == "NEW"]
    if not new:
        return
    body = (f"Cloud Watchdog found {len(new)} new issue(s):\n\n"
            + "\n".join(_line(f) for f in new)
            + f"\n\nGrade: {summary['grade']} ({summary['score']}/100). "
              f"About ${summary['wasted_usd']:.2f}/month wasted.\n"
              "Open the dashboard to Fix, Delete or Ignore them.")
    boto3.client("sns").publish(TopicArn=SNS_TOPIC_ARN,
                                Subject=f"Cloud Watchdog: {len(new)} new issue(s)",
                                Message=body)


def email_reminder(findings):
    """Mondays (UTC): remind about anything OPEN for REMINDER_DAYS or more."""
    now = datetime.now(timezone.utc)
    if now.weekday() != 0:                       # 0 = Monday
        return
    cutoff = now - timedelta(days=REMINDER_DAYS)
    old = [f for f in findings if f["status"] == "OPEN"
           and datetime.strptime(f["first_seen"], "%Y-%m-%dT%H:%M:%SZ")
                       .replace(tzinfo=timezone.utc) <= cutoff]
    if not old:
        return
    body = (f"Weekly reminder: {len(old)} issue(s) have been open for {REMINDER_DAYS}+ days:\n\n"
            + "\n".join(_line(f) for f in old))
    boto3.client("sns").publish(TopicArn=SNS_TOPIC_ARN,
                                Subject=f"Cloud Watchdog: {len(old)} issue(s) still open",
                                Message=body)


# -------------------------------------------------------------- whole scan

def scan(scheduled=False):
    """Run the checks, compare with last time, save, email. Returns (summary, findings)."""
    scanned_at = now_iso()
    current, errors = run_checks()

    if not FINDINGS_TABLE:                       # CloudShell test: nothing to compare or save
        findings = update_state(current, {})
        return build_summary(findings, errors, scanned_at), findings

    table = boto3.resource("dynamodb").Table(FINDINGS_TABLE)
    findings = update_state(current, load_previous(table))
    save_findings(table, findings)

    summary = build_summary(findings, errors, scanned_at)
    if REPORTS_BUCKET:
        summary["report_key"] = save_report(summary, findings)
    if SNS_TOPIC_ARN:
        email_new(findings, summary)
        if scheduled:                            # only the daily run sends the reminder
            email_reminder(findings)
    return summary, findings


def lambda_handler(event, context):
    """Entry point on AWS. EventBridge events have source 'aws.events';
    'Scan now' (via the actions Lambda) sends an empty event."""
    summary, _ = scan(scheduled=(event or {}).get("source") == "aws.events")
    print(json.dumps(summary))                   # shows up in CloudWatch Logs
    if summary["errors"]:
        # Everything that worked is already saved. Failing now makes the
        # CloudWatch alarm on scanner errors email the SNS topic.
        raise RuntimeError("Scan finished with errors: " + "; ".join(summary["errors"]))
    return summary


# ------------------------------------------------------- CloudShell output

def print_report(summary, findings):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    active = sorted((f for f in findings if f["status"] in ("NEW", "OPEN")),
                    key=lambda f: (order[f["severity"]], f["check"]))

    print(f"{'STATUS':<6} {'SEVERITY':<8} {'CHECK':<17} {'REGION':<10} {'$/MONTH':>8}  "
          f"{'CIS':<9} RESOURCE / DETAIL")
    for f in active:
        cost = f"{f['est_monthly_usd']:.2f}" if f.get("est_monthly_usd") is not None else "-"
        print(f"{f['status']:<6} {f['severity']:<8} {f['check']:<17} {f['region']:<10} {cost:>8}  "
              f"{f.get('cis') or '-':<9} {f['resource_name']}  ({f['resource_id']})")
        print(f"{'':<63}{f['detail']}")

    s = summary
    print(f"\n{len(active)} open findings ({s['new']} new), "
          f"about ${s['wasted_usd']:.2f}/month wasted")
    print(f"Grade {s['grade']} ({s['score']}/100). "
          f"Fixed so far: {s['fixed_total']}, saving ${s['saved_usd']:.2f}/month")
    if not FINDINGS_TABLE:
        print("(FINDINGS_TABLE not set: nothing saved, everything shows as NEW)")
    for e in s["errors"]:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    print_report(*scan())
