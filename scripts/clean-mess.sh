#!/usr/bin/env bash
# clean-mess.sh — delete everything plant-mess.sh created.
#
# Finds resources by the tag watchdog-test=true (and the test bucket by name),
# so it never touches anything else. Safe to run more than once: if something
# is already gone, it just skips it.
#
# Usage:  bash scripts/clean-mess.sh

set -euo pipefail

REGIONS=("us-east-1" "us-west-2")
TAG_FILTER="Name=tag:watchdog-test,Values=true"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Cleaning test mess in account ${ACCOUNT_ID}"

for REGION in "${REGIONS[@]}"; do
  echo
  echo "== ${REGION} =="

  # 1. Terminate test instances first (they may hold other resources)
  INSTANCES=$(aws ec2 describe-instances --region "$REGION" \
    --filters "$TAG_FILTER" Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].InstanceId' --output text)
  if [[ -n "$INSTANCES" ]]; then
    aws ec2 terminate-instances --region "$REGION" --instance-ids $INSTANCES > /dev/null
    echo "Terminating instances: $INSTANCES (waiting...)"
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids $INSTANCES
  fi

  # 2. Release Elastic IPs
  for ALLOC in $(aws ec2 describe-addresses --region "$REGION" \
      --filters "$TAG_FILTER" --query 'Addresses[].AllocationId' --output text); do
    aws ec2 release-address --region "$REGION" --allocation-id "$ALLOC"
    echo "Released Elastic IP:   $ALLOC"
  done

  # 3. Delete loose volumes (only ones not attached)
  for VOL in $(aws ec2 describe-volumes --region "$REGION" \
      --filters "$TAG_FILTER" Name=status,Values=available \
      --query 'Volumes[].VolumeId' --output text); do
    aws ec2 delete-volume --region "$REGION" --volume-id "$VOL"
    echo "Deleted volume:        $VOL"
  done

  # 4. Delete snapshots of test volumes (the app's "Fix" for EBS makes one first)
  for SNAP in $(aws ec2 describe-snapshots --region "$REGION" --owner-ids self \
      --filters "$TAG_FILTER" --query 'Snapshots[].SnapshotId' --output text); do
    aws ec2 delete-snapshot --region "$REGION" --snapshot-id "$SNAP"
    echo "Deleted snapshot:      $SNAP"
  done

  # 5. Delete test security groups
  for SG in $(aws ec2 describe-security-groups --region "$REGION" \
      --filters "$TAG_FILTER" --query 'SecurityGroups[].GroupId' --output text); do
    aws ec2 delete-security-group --region "$REGION" --group-id "$SG"
    echo "Deleted security group: $SG"
  done
done

# 6. Empty and delete the test bucket (S3 is global, so once, outside the loop)
BUCKET="watchdog-test-public-${ACCOUNT_ID}"
echo
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  aws s3 rm "s3://${BUCKET}" --recursive > /dev/null
  aws s3api delete-bucket --bucket "$BUCKET"
  echo "Deleted bucket:        $BUCKET"
else
  echo "Bucket already gone:   $BUCKET"
fi

echo
echo "Clean."
