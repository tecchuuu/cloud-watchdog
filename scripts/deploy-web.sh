#!/usr/bin/env bash
# deploy-web.sh — upload the dashboard (web/) to Amplify.
#
# 1. Asks for the three values from the manual steps (README 8-9):
#    API Gateway Invoke URL, Cognito domain, Cognito client ID.
#    Your answers are remembered in ~/.watchdog-web for next time.
# 2. Reads amplify_app_id and dashboard_url from `tofu output`.
# 3. Writes web/config.js, zips web/, and uploads it as a manual Amplify deployment:
#    create-deployment -> PUT the zip to the URL it returns -> start-deployment.
#
# Usage (from the repo folder): bash scripts/deploy-web.sh

set -euo pipefail
cd "$(dirname "$0")/.."

SAVED=~/.watchdog-web
[ -f "$SAVED" ] && source "$SAVED"

ask() {  # ask "question" VAR_NAME  (Enter keeps the remembered value)
  local current="${!2:-}" answer
  read -rp "$1${current:+ [$current]}: " answer
  answer="${answer:-$current}"
  answer="${answer%/}"                       # no trailing slash
  [ -n "$answer" ] || { echo "Needed, stopping."; exit 1; }
  printf -v "$2" '%s' "$answer"
}

ask "API Gateway Invoke URL" API_URL
ask "Cognito domain"         COGNITO_DOMAIN
ask "Cognito client ID"      CLIENT_ID
[[ "$COGNITO_DOMAIN" == https://* ]] || COGNITO_DOMAIN="https://$COGNITO_DOMAIN"

printf 'API_URL=%q\nCOGNITO_DOMAIN=%q\nCLIENT_ID=%q\n' "$API_URL" "$COGNITO_DOMAIN" "$CLIENT_ID" > "$SAVED"

# Values tofu made (infra/outputs.tf). If CloudShell restarted, /tmp/tofu-data
# is empty and tofu needs `tofu init` first, so do that once and try again.
if ! OUTPUTS=$(cd infra && tofu output -json 2>/dev/null); then
  echo "Running tofu init (CloudShell was restarted)…"
  (cd infra && tofu init -input=false > /dev/null)
  OUTPUTS=$(cd infra && tofu output -json)
fi
out() { python3 -c "import json,sys; print(json.load(sys.stdin)['$1']['value'])" <<< "$OUTPUTS"; }
APP_ID=$(out amplify_app_id)
DASHBOARD_URL=$(out dashboard_url)

cat > web/config.js <<EOF
// Written by scripts/deploy-web.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Not committed.
window.CONFIG = {
  apiUrl: "$API_URL",
  cognitoDomain: "$COGNITO_DOMAIN",
  clientId: "$CLIENT_ID",
  redirectUri: "$DASHBOARD_URL",
};
EOF
echo "Wrote web/config.js"

# Zip the site (files at the top of the zip, not inside a web/ folder)
ZIP=/tmp/watchdog-web.zip
rm -f "$ZIP"
(cd web && python3 -m zipfile -c "$ZIP" index.html config.js auth.js app.js style.css)

# Manual deployment: Amplify gives a one-time upload URL, we PUT the zip there, then start it
JOB=$(aws amplify create-deployment --app-id "$APP_ID" --branch-name main --output json)
JOB_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['jobId'])" <<< "$JOB")
UPLOAD_URL=$(python3 -c "import json,sys; print(json.load(sys.stdin)['zipUploadUrl'])" <<< "$JOB")

curl -sSf -X PUT -H "Content-Type: application/zip" --upload-file "$ZIP" "$UPLOAD_URL" > /dev/null
aws amplify start-deployment --app-id "$APP_ID" --branch-name main --job-id "$JOB_ID" > /dev/null
echo "Uploaded, deploying (job $JOB_ID)…"

for _ in $(seq 30); do
  STATUS=$(aws amplify get-job --app-id "$APP_ID" --branch-name main --job-id "$JOB_ID" \
           --query 'job.summary.status' --output text)
  case "$STATUS" in
    SUCCEED) echo "Done. Open $DASHBOARD_URL"; exit 0 ;;
    FAILED|CANCELLED) echo "Deployment $STATUS. See Amplify -> watchdog-dashboard -> main in the console."; exit 1 ;;
  esac
  sleep 2
done
echo "Still deploying after a minute; check Amplify in the console, then open $DASHBOARD_URL"
