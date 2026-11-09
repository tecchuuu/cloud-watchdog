# Cloud Watchdog

Cloud Watchdog scans an AWS account for wasted money and security risks, shows them on a dashboard, and lets you **Fix**, **Delete** or **Ignore** each finding. It scans every day on its own and emails a summary of new issues.

Built for small IT teams (2–10 people) that run AWS without a dedicated cloud security person.

> CS446/IT332 Cloud Computing, Bangkok University, 2026. Runs in an AWS Academy Learner Lab.

## AWS services

| Service | Job |
|---|---|
| Lambda | `watchdog-scanner` finds problems; `watchdog-actions` does Fix / Delete / Ignore |
| EventBridge | Runs the scanner once a day |
| DynamoDB | `watchdog_findings` (latest results) and `watchdog_actions` (audit log) |
| S3 | Stores JSON scan reports |
| SNS | Emails new issues |
| API Gateway | HTTP API the dashboard calls, protected by a Cognito login token |
| Amplify | Hosts the dashboard |
| Cognito | Dashboard login (admin-created accounts only) |

## Repo layout

```
cloud-watchdog/
├── infra/      OpenTofu: main.tf, variables.tf, outputs.tf
├── lambda/     scanner.py, actions.py
├── web/        dashboard (index.html, app.js, style.css)
├── scripts/    plant-mess.sh, clean-mess.sh, deploy-web.sh
└── docs/       architecture.tex
```

## Setup and deploy

_Written step by step as each part is built. Not ready to follow yet._

## Demo

_Coming soon._

## Cleanup

_Coming soon._
