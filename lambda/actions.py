"""
actions.py — Fix / Delete / Ignore for Cloud Watchdog findings,
with a tamper-evident (hash-chained) audit log.

Every action follows the same steps:
  1. Look up the finding in DynamoDB (the resource comes from there, never from the request)
  2. Re-read the resource in AWS: gone or no longer a problem -> ALREADY_FIXED
  3. Safety rules: protected resources are refused
  4. Do it
  5. Write an audit log entry (who, what, when, result, hash chain)
  6. Update the finding's status

Fix   = remove the risk, keep the resource (reversible)
Delete = remove the resource (not reversible; the dashboard asks to confirm)
Ignore = tag it watchdog-ignore=true so future scans skip it, and keep the reason

CloudShell test mode (before API Gateway exists):
    python3 lambda/actions.py list
    python3 lambda/actions.py preview-fix   '<finding_id>' ...   (or: all)
    python3 lambda/actions.py fix           '<finding_id>' ... --user magi
    python3 lambda/actions.py delete        '<finding_id>' ... --user magi
    python3 lambda/actions.py ignore        '<finding_id>' --reason "why" --user magi
    python3 lambda/actions.py log
    python3 lambda/actions.py verify
"""

import argparse
import hashlib
import json
import os
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

import scanner as sc   # shared helpers: tag_dict, now_iso, bucket checks, port logic

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "watchdog_findings")
ACTIONS_TABLE = os.environ.get("ACTIONS_TABLE", "watchdog_actions")

GENESIS_HASH = "0" * 64            # prev_hash of the very first log entry
IGNORE_TAG = {"Key": "watchdog-ignore", "Value": "true"}

_dynamodb = boto3.resource("dynamodb")
findings_table = _dynamodb.Table(FINDINGS_TABLE)
log_table = _dynamodb.Table(ACTIONS_TABLE)


# ----------------------------------------------------------------- helpers

def _not_found(error):
    """Does this AWS error mean 'that resource doesn't exist (any more)'?"""
    code = error.response["Error"]["Code"]
    return code.endswith("NotFound") or code in ("NoSuchBucket", "404")


def _ec2(f):
    return boto3.client("ec2", region_name=f["region"])


def _tag_ec2(f, info):
    """Ignore for EC2-family resources (EIP, security group, volume, instance)."""
    _ec2(f).create_tags(Resources=[f["resource_id"]], Tags=[IGNORE_TAG])


# Each check below has four functions:
#   inspect(f) -> None if the resource is gone, otherwise a dict:
#       problem: is it still a problem right now?
#       tags:    its current tags (for the safety rules)
#       fix / delete: one line saying what that button would do (for the preview)
#   fix(f, info)    -> does Fix, returns "before" (what to undo), or None
#   delete(f, info) -> does Delete
#   tag(f, info)    -> does Ignore


# ---------------------------------------------------- 1. unused Elastic IP

def eip_inspect(f):
    try:
        addr = _ec2(f).describe_addresses(AllocationIds=[f["resource_id"]])["Addresses"][0]
    except ClientError as e:
        if _not_found(e):
            return None
        raise
    ip = addr["PublicIp"]
    return {"problem": "AssociationId" not in addr,      # attached now = in use = fine
            "tags": sc.tag_dict(addr.get("Tags")),
            "fix": f"Release Elastic IP {ip}",
            "delete": f"Release Elastic IP {ip}"}


def eip_release(f, info):
    # Fix and Delete are the same thing: an unused IP has nothing worth keeping.
    _ec2(f).release_address(AllocationId=f["resource_id"])


# ---------------------------------------------- 2. admin ports open to all

def _world_admin_rules(sg):
    """The parts of the inbound rules that open admin ports to the whole internet,
    in the exact shape revoke_security_group_ingress needs. Other sources stay."""
    rules = []
    for perm in sg.get("IpPermissions", []):
        ports, _ = sc._open_admin_ports(perm)
        if not ports:
            continue
        base = {"IpProtocol": perm["IpProtocol"]}
        if perm["IpProtocol"] != "-1":
            base.update(FromPort=perm["FromPort"], ToPort=perm["ToPort"])
        if any(r.get("CidrIp") == sc.WORLD_IPV4 for r in perm.get("IpRanges", [])):
            rules.append({**base, "IpRanges": [{"CidrIp": sc.WORLD_IPV4}]})
        if any(r.get("CidrIpv6") == sc.WORLD_IPV6 for r in perm.get("Ipv6Ranges", [])):
            rules.append({**base, "Ipv6Ranges": [{"CidrIpv6": sc.WORLD_IPV6}]})
    return rules


def sg_inspect(f):
    try:
        sg = _ec2(f).describe_security_groups(GroupIds=[f["resource_id"]])["SecurityGroups"][0]
    except ClientError as e:
        if _not_found(e):
            return None
        raise
    rules = _world_admin_rules(sg)
    ports = sorted({p for perm in sg.get("IpPermissions", []) for p in sc._open_admin_ports(perm)[0]})
    info = {"problem": bool(rules),
            "tags": sc.tag_dict(sg.get("Tags")),
            "rules": rules,
            "fix": f"Remove {', '.join(ports) or 'admin port'} access from the internet on {sg['GroupName']}",
            "delete": f"Delete security group {sg['GroupName']} (fails if something still uses it)"}
    if sg["GroupName"] == "default":
        info["protected"] = "default security groups are never changed"
    return info


def sg_fix(f, info):
    _ec2(f).revoke_security_group_ingress(GroupId=f["resource_id"], IpPermissions=info["rules"])
    return {"revoked_rules": info["rules"]}          # enough to add them back (undo)


def sg_delete(f, info):
    _ec2(f).delete_security_group(GroupId=f["resource_id"])


# ------------------------------------------------------- 3. public bucket

def _s3(f):
    return boto3.client("s3", region_name=f["region"])


def bucket_inspect(f):
    s3, name = _s3(f), f["resource_id"]
    try:
        s3.head_bucket(Bucket=name)
    except ClientError as e:
        if _not_found(e):
            return None
        raise
    block = sc._bucket_block_settings(s3, name)
    public = ((sc._policy_is_public(s3, name) and not block.get("RestrictPublicBuckets"))
              or (sc._acl_is_public(s3, name) and not block.get("IgnorePublicAcls")))
    return {"problem": public,
            "tags": sc._bucket_tags(s3, name),
            "block": block,
            "fix": f"Turn on Block Public Access for bucket {name}",
            "delete": f"Delete every object in bucket {name}, then the bucket"}


def bucket_fix(f, info):
    _s3(f).put_public_access_block(
        Bucket=f["resource_id"],
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return {"public_access_block": info["block"]}    # the old switches (undo)


def bucket_delete(f, info):
    bucket = boto3.resource("s3", region_name=f["region"]).Bucket(f["resource_id"])
    bucket.object_versions.delete()                  # every object (and old version)
    bucket.delete()


def bucket_tag(f, info):
    # put_bucket_tagging REPLACES all tags, so keep the existing ones and add ours.
    tags = {**info["tags"], IGNORE_TAG["Key"]: IGNORE_TAG["Value"]}
    _s3(f).put_bucket_tagging(Bucket=f["resource_id"],
                              Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]})


# ------------------------------------------------- 4. unattached EBS volume

def ebs_inspect(f):
    try:
        vol = _ec2(f).describe_volumes(VolumeIds=[f["resource_id"]])["Volumes"][0]
    except ClientError as e:
        if _not_found(e):
            return None
        raise
    return {"problem": vol["State"] == "available",  # attached now = in use = fine
            "tags": sc.tag_dict(vol.get("Tags")),
            "fix": f"Snapshot {vol['VolumeId']} ({vol['Size']} GiB), then delete the volume",
            "delete": f"Delete volume {vol['VolumeId']} ({vol['Size']} GiB), no snapshot"}


def ebs_fix(f, info):
    ec2, vol_id = _ec2(f), f["resource_id"]
    # Copy the volume's tags to the snapshot (AWS-reserved "aws:" tags can't be copied).
    tags = [{"Key": k, "Value": v} for k, v in info["tags"].items() if not k.startswith("aws:")]
    tags.append({"Key": "watchdog-backup-of", "Value": vol_id})
    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        Description=f"Cloud Watchdog backup of {vol_id} before delete",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tags}])
    # The snapshot is taken at this moment; the volume can be deleted while it finishes.
    ec2.delete_volume(VolumeId=vol_id)
    return {"snapshot_id": snap["SnapshotId"]}       # restore the volume from this (undo)


def ebs_delete(f, info):
    _ec2(f).delete_volume(VolumeId=f["resource_id"])


# --------------------------------------------------------- 5. idle EC2

def ec2_inspect(f):
    try:
        res = _ec2(f).describe_instances(InstanceIds=[f["resource_id"]])["Reservations"]
    except ClientError as e:
        if _not_found(e):
            return None
        raise
    inst = res[0]["Instances"][0]
    state = inst["State"]["Name"]
    if state in ("shutting-down", "terminated"):
        return None
    return {"problem": state == "running",           # stopped already = no compute cost
            "tags": sc.tag_dict(inst.get("Tags")),
            "fix": f"Stop instance {inst['InstanceId']} ({inst['InstanceType']}); its disk is kept",
            "delete": f"Terminate instance {inst['InstanceId']} ({inst['InstanceType']}) and its root disk"}


def ec2_stop(f, info):
    _ec2(f).stop_instances(InstanceIds=[f["resource_id"]])
    return {"state": "running"}                      # start it again (undo)


def ec2_terminate(f, info):
    _ec2(f).terminate_instances(InstanceIds=[f["resource_id"]])


HANDLERS = {
    "unused_eip":       {"inspect": eip_inspect,    "fix": eip_release, "delete": eip_release,    "tag": _tag_ec2},
    "open_admin_ports": {"inspect": sg_inspect,     "fix": sg_fix,      "delete": sg_delete,      "tag": _tag_ec2},
    "public_bucket":    {"inspect": bucket_inspect, "fix": bucket_fix,  "delete": bucket_delete,  "tag": bucket_tag},
    "unattached_ebs":   {"inspect": ebs_inspect,    "fix": ebs_fix,     "delete": ebs_delete,     "tag": _tag_ec2},
    "idle_ec2":         {"inspect": ec2_inspect,    "fix": ec2_stop,    "delete": ec2_terminate,  "tag": _tag_ec2},
}


# ------------------------------------------------------------ safety rules

def _protected_reason(info):
    """Why the Watchdog must not touch this resource, or None if it may."""
    if info["tags"].get("managed-by") == "watchdog":
        return "it is part of the Watchdog itself (managed-by=watchdog)"
    if info["tags"].get("watchdog-ignore") == "true":
        return "it is ignored (watchdog-ignore=true)"
    return info.get("protected")                      # e.g. default security group


# --------------------------------------------------------------- actions

def _get_finding(finding_id):
    item = findings_table.get_item(Key={"finding_id": finding_id}).get("Item")
    return {k: float(v) if isinstance(v, Decimal) else v for k, v in item.items()} if item else None


def preview(action, finding_ids):
    """What would FIX or DELETE do to each finding? Changes nothing."""
    out = []
    for fid in finding_ids:
        f = _get_finding(fid)
        if not f or f["check"] not in HANDLERS:
            out.append({"finding_id": fid, "will": "Nothing: unknown finding"})
            continue
        info = HANDLERS[f["check"]]["inspect"](f)
        if info is None or not info["problem"]:
            will = "Nothing: already fixed or gone"
        elif reason := _protected_reason(info):
            will = f"Nothing: refused, {reason}"
        else:
            will = info[action.lower()]
        out.append({"finding_id": fid, "resource_name": f["resource_name"],
                    "region": f["region"], "will": will})
    return out


def run(action, finding_id, user, reason=None):
    """Do one FIX / DELETE / IGNORE. Always writes a log entry. Returns the result."""
    f = _get_finding(finding_id)
    before, error, done = None, None, None

    if not f or f["check"] not in HANDLERS:
        result, error = "FAILED", "unknown finding"
    elif action == "IGNORE" and not (reason or "").strip():
        result, error = "FAILED", "Ignore needs a reason"
    else:
        h = HANDLERS[f["check"]]
        try:
            info = h["inspect"](f)                                   # 2. re-check first
            if info is None or (action != "IGNORE" and not info["problem"]):
                result = "ALREADY_FIXED"
            elif why := _protected_reason(info):                     # 3. safety rules
                result, error = "FAILED", f"refused: {why}"
            else:                                                    # 4. do it
                if action == "FIX":
                    before = h["fix"](f, info)
                    done = info["fix"]
                elif action == "DELETE":
                    h["delete"](f, info)
                    done = info["delete"]
                else:
                    h["tag"](f, info)
                    done = "Tagged watchdog-ignore=true"
                result = "OK"
        except ClientError as e:                                     # e.g. SG still in use
            result, error = "FAILED", e.response["Error"].get("Message", str(e))

    entry = append_log(user=user, action=action, finding_id=finding_id, result=result,  # 5.
                       reason=reason, error=error,
                       before=json.dumps(before, default=str) if before else None)

    if f and (result == "ALREADY_FIXED" or (result == "OK" and action != "IGNORE")):   # 6.
        findings_table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="SET #s = :s, fixed_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "FIXED", ":t": sc.now_iso()})
    elif f and result == "OK" and action == "IGNORE":
        findings_table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="SET #s = :s, ignore_reason = :r",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "IGNORED", ":r": reason})

    return {"finding_id": finding_id, "action": action, "result": result,
            "done": done, "error": error, "log_seq": entry["seq"]}


def run_many(action, finding_ids, user, reason=None):
    """Fix selected / Delete selected / Fix all: one at a time, each logged."""
    return [run(action, fid, user, reason) for fid in finding_ids]


# ------------------------------------------------- audit log (hash chain)
#
# Each entry stores the hash of the entry before it (prev_hash) and its own
# hash, computed over every field except "hash". Change any old entry and
# its hash no longer matches; change its hash too and the next entry's
# prev_hash no longer matches. Verify walks the chain and finds the break.

def _plain(value):
    """DynamoDB gives numbers back as Decimal; make them plain ints again."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"can't hash {type(value)}")


def _hash(entry):
    """SHA-256 of the entry as canonical JSON: keys sorted, no spaces, without 'hash'."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=_plain)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _last_entry():
    resp = log_table.query(KeyConditionExpression=Key("pk").eq("LOG"),
                           ScanIndexForward=False, Limit=1,           # newest first, just one
                           ConsistentRead=True)
    return resp["Items"][0] if resp["Items"] else None


def append_log(**fields):
    """Add one entry to the end of the chain."""
    for _ in range(5):
        last = _last_entry()
        entry = {"pk": "LOG",
                 "seq": int(last["seq"]) + 1 if last else 1,
                 "ts": sc.now_iso(),
                 "prev_hash": last["hash"] if last else GENESIS_HASH}
        entry.update({k: v for k, v in fields.items() if v is not None})
        entry["hash"] = _hash(entry)
        try:
            # Only succeeds if nobody has taken this seq yet. If two admins act
            # at the same moment, the second one retries with the next number.
            log_table.put_item(Item=entry, ConditionExpression="attribute_not_exists(seq)")
            return entry
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
    raise RuntimeError("could not write the audit log entry after 5 tries")


def read_log():
    """Every entry, oldest first."""
    entries, kwargs = [], {}
    while True:
        page = log_table.query(KeyConditionExpression=Key("pk").eq("LOG"),
                               ConsistentRead=True, **kwargs)
        entries += page["Items"]
        if "LastEvaluatedKey" not in page:
            return entries
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def verify_log():
    """Walk seq 1..N. Returns {ok, broken_at, entries}; broken_at = first bad seq."""
    log = read_log()
    expected_seq, expected_prev = 1, GENESIS_HASH
    for e in log:
        seq = int(e["seq"])
        if seq != expected_seq:                     # an entry is missing
            return {"ok": False, "broken_at": expected_seq, "entries": len(log)}
        if e.get("prev_hash") != expected_prev or _hash(e) != e.get("hash"):
            return {"ok": False, "broken_at": seq, "entries": len(log)}
        expected_seq, expected_prev = seq + 1, e["hash"]
    return {"ok": True, "broken_at": None, "entries": len(log)}


# ----------------------------------------------------- CloudShell test mode

def _cli():
    p = argparse.ArgumentParser(description="Cloud Watchdog actions (test mode)")
    p.add_argument("command", choices=["list", "preview-fix", "preview-delete",
                                       "fix", "delete", "ignore", "log", "verify"])
    p.add_argument("finding_ids", nargs="*")
    p.add_argument("--user", default="cli-test", help="name written to the audit log")
    p.add_argument("--reason", help="required for ignore")
    a = p.parse_args()

    active = [f for f in findings_table.scan()["Items"] if f["status"] in ("NEW", "OPEN")]
    if a.finding_ids == ["all"]:                     # like the dashboard's "Fix all"
        a.finding_ids = [f["finding_id"] for f in active]

    if a.command == "list":
        for f in active:
            print(f"{f['status']:<5} {f['severity']:<6} {f['resource_name']:<36} {f['finding_id']}")
    elif a.command.startswith("preview-"):
        for r in preview(a.command.split("-")[1].upper(), a.finding_ids):
            print(f"{r.get('resource_name', r['finding_id'])}: {r['will']}")
    elif a.command in ("fix", "delete", "ignore"):
        for r in run_many(a.command.upper(), a.finding_ids, a.user, a.reason):
            print(f"[log #{r['log_seq']}] {r['result']:<13} {r['finding_id']}  "
                  f"{r['done'] or r['error'] or ''}")
    elif a.command == "log":
        for e in read_log():
            print(f"#{int(e['seq']):<3} {e['ts']}  {e['user']:<10} {e['action']:<7} "
                  f"{e['result']:<13} {e['finding_id']}  hash {e['hash'][:12]}…")
    elif a.command == "verify":
        print(json.dumps(verify_log()))


if __name__ == "__main__":
    _cli()
