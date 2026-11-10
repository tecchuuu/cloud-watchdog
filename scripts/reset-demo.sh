#!/usr/bin/env bash
# reset-demo.sh — wipe Watchdog's memory so a demo starts from zero.
#
# Empties:  watchdog_findings (all findings), watchdog_actions (the audit log),
#           and reports/ in the reports bucket (the Report tab's history).
# Keeps:    every service: Lambdas, API Gateway, Cognito, Amplify, the schedule.
#
# Why not `tofu destroy` + `tofu apply`? That would also make a new Amplify app
# with a new URL, and Cognito + API Gateway CORS (set up by hand) point at the old one.
#
# Usage: bash scripts/reset-demo.sh      (asks you to type RESET first)

set -euo pipefail

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="watchdog-reports-${ACCOUNT_ID}"

echo "This deletes ALL findings, the whole audit log and the scan history"
echo "(tables watchdog_findings, watchdog_actions; s3://${BUCKET}/reports/)."
read -rp "Type RESET to continue: " answer
[[ "$answer" == "RESET" ]] || { echo "Cancelled, nothing changed."; exit 1; }

python3 - <<'EOF'
import boto3

dynamodb = boto3.resource("dynamodb")
for name, keys in [("watchdog_findings", ["finding_id"]), ("watchdog_actions", ["pk", "seq"])]:
    table = dynamodb.Table(name)
    count, kwargs = 0, {"ProjectionExpression": ", ".join(f"#{i}" for i in range(len(keys))),
                        "ExpressionAttributeNames": {f"#{i}": k for i, k in enumerate(keys)}}
    with table.batch_writer() as batch:
        while True:
            page = table.scan(**kwargs)
            for item in page["Items"]:
                batch.delete_item(Key={k: item[k] for k in keys})
                count += 1
            if "LastEvaluatedKey" not in page:
                break
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    print(f"{name}: deleted {count} items")
EOF

aws s3 rm "s3://${BUCKET}/reports/" --recursive --quiet
echo "s3://${BUCKET}/reports/: emptied"
echo
echo "Done. Refresh the dashboard: no findings, empty log, no history."
