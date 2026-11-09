#!/usr/bin/env bash
# plant-mess.sh — create test problems for Cloud Watchdog to find.
#
# Creates (all in us-east-1, all tagged watchdog-test=true):
#   1. An Elastic IP that is not attached to anything      -> cost finding
#   2. A security group with SSH (22) open to the world    -> security finding
#   3. A public S3 bucket                                  -> security finding
#   4. A 1 GiB EBS volume that is not attached             -> cost finding
#   --ec2: also a t3.micro instance left idle              -> cost finding (needs hours of CPU data)
#
# Usage:  bash scripts/plant-mess.sh          (the 4 quick problems)
#         bash scripts/plant-mess.sh --ec2    (also the idle EC2)
# Undo:   bash scripts/clean-mess.sh

set -euo pipefail   # stop on the first error, unset variable, or failed pipe

REGION="us-east-1"
TAG_KEY="watchdog-test"
TAG_VALUE="true"

LAUNCH_EC2=false
if [[ "${1:-}" == "--ec2" ]]; then
  LAUNCH_EC2=true
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Planting mess in account ${ACCOUNT_ID}, region ${REGION}"
echo

# ---------------------------------------------------------------- 1. Elastic IP
EIP_ALLOC=$(aws ec2 allocate-address \
  --region "$REGION" \
  --domain vpc \
  --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=Name,Value=watchdog-test-eip}]" \
  --query AllocationId --output text)
echo "[1/4] Elastic IP allocated, not attached:   ${EIP_ALLOC}"

# ---------------------------------------------- 2. Security group with open SSH
VPC_ID=$(aws ec2 describe-vpcs \
  --region "$REGION" \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)

SG_NAME="watchdog-test-open-ssh"
SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters Name=group-name,Values="$SG_NAME" Name=vpc-id,Values="$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text)

if [[ "$SG_ID" == "None" ]]; then
  SG_ID=$(aws ec2 create-security-group \
    --region "$REGION" \
    --group-name "$SG_NAME" \
    --description "Cloud Watchdog test: SSH open to the world" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}}]" \
    --query GroupId --output text)
  aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null
  echo "[2/4] Security group with SSH open to 0.0.0.0/0: ${SG_ID}"
else
  echo "[2/4] Security group already exists, reusing: ${SG_ID}"
fi

# ------------------------------------------------------------ 3. Public bucket
BUCKET="watchdog-test-public-${ACCOUNT_ID}"

if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "[3/4] Bucket already exists, reusing:     ${BUCKET}"
else
  aws s3api create-bucket --region "$REGION" --bucket "$BUCKET" > /dev/null
  aws s3api put-bucket-tagging --bucket "$BUCKET" \
    --tagging "TagSet=[{Key=${TAG_KEY},Value=${TAG_VALUE}}]"
  echo "[3/4] Bucket created:                      ${BUCKET}"
fi

# New buckets block public access by default; turn that off for this bucket only.
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

# Policy: anyone on the internet can read any object in the bucket.
POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "WatchdogTestPublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::${BUCKET}/*"
  }]
}
EOF
)
if aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$POLICY"; then
  echo "      ...made public with a GetObject-for-everyone policy"
else
  echo "      !!! Could not make the bucket public. Account-level Block Public Access may be on."
fi

# -------------------------------------------------------- 4. Loose EBS volume
VOL_ID=$(aws ec2 create-volume \
  --region "$REGION" \
  --availability-zone "${REGION}a" \
  --size 1 --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=Name,Value=watchdog-test-volume}]" \
  --query VolumeId --output text)
echo "[4/4] 1 GiB gp3 volume, not attached:      ${VOL_ID}"

# ------------------------------------------------------ Optional: idle EC2
if [[ "$LAUNCH_EC2" == true ]]; then
  AMI_ID=$(aws ssm get-parameter \
    --region "$REGION" \
    --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query Parameter.Value --output text)
  INSTANCE_ID=$(aws ec2 run-instances \
    --region "$REGION" \
    --image-id "$AMI_ID" \
    --instance-type t3.micro \
    --count 1 \
    --tag-specifications "ResourceType=instance,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=Name,Value=watchdog-test-idle}]" \
    --query 'Instances[0].InstanceId' --output text)
  echo "[ec2] Idle t3.micro launched:              ${INSTANCE_ID}"
  echo "      (the idle check needs IDLE_HOURS of CPU data before it flags this)"
fi

echo
echo "Done. Everything is tagged ${TAG_KEY}=${TAG_VALUE}."
