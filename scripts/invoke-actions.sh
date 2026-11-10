#!/usr/bin/env bash
# invoke-actions.sh — call the watchdog-actions Lambda the way API Gateway will,
# so the API can be tested before API Gateway and Cognito exist.
#
# It fakes the part API Gateway adds after checking the login token
# (requestContext.authorizer.jwt.claims), with the username you give.
#
# Usage:
#   bash scripts/invoke-actions.sh "GET /findings"
#   bash scripts/invoke-actions.sh "GET /report"
#   bash scripts/invoke-actions.sh "GET /verify-log"
#   bash scripts/invoke-actions.sh "POST /scan"
#   bash scripts/invoke-actions.sh "POST /preview" '{"action":"FIX","finding_ids":["<id>"]}'
#   bash scripts/invoke-actions.sh "POST /fix"     '{"finding_ids":["<id>"]}'
#   bash scripts/invoke-actions.sh "POST /ignore"  '{"finding_id":"<id>","reason":"why"}'
#
# Username in the log: TEST_USER=magi bash scripts/invoke-actions.sh ...

set -euo pipefail

ROUTE="${1:?route, e.g. \"GET /report\"}"
BODY="${2:-}"
USER_NAME="${TEST_USER:-cli-test}"

EVENT=$(python3 - "$ROUTE" "$BODY" "$USER_NAME" <<'EOF'
import json, sys
route, body, user = sys.argv[1:4]
method, path = route.split(" ", 1)
print(json.dumps({
    "routeKey": route,
    "rawPath": path,
    "body": body or None,
    "requestContext": {"http": {"method": method, "path": path},
                       "authorizer": {"jwt": {"claims": {"cognito:username": user}}}},
}))
EOF
)

aws lambda invoke \
  --function-name watchdog-actions \
  --cli-binary-format raw-in-base64-out \
  --cli-read-timeout 60 \
  --payload "$EVENT" \
  /tmp/actions-out.json > /dev/null

# Print the status code, then the body pretty-printed
python3 - <<'EOF'
import json
resp = json.load(open("/tmp/actions-out.json"))
print("HTTP", resp.get("statusCode"))
try:
    print(json.dumps(json.loads(resp.get("body") or "null"), indent=2))
except (TypeError, ValueError):
    print(resp)
EOF
