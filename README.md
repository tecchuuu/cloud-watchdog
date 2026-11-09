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

_Written step by step as each part is built. Steps below are tested; more are coming._

Everything runs in **AWS CloudShell** inside an AWS Academy Learner Lab. Nothing needs to be installed on your own computer.

### 1. Open CloudShell

1. Start the Learner Lab and open the AWS Console.
2. Check the region (top right) is **N. Virginia (us-east-1)**.
3. Click the CloudShell icon (`>_`) in the top bar and wait for the prompt.

### 2. Get the code

```bash
git clone https://github.com/tecchuuu/cloud-watchdog.git
cd cloud-watchdog
```

### 3. Keep OpenTofu's files out of your home folder

CloudShell's home folder is only **1 GB**, and the AWS plugin OpenTofu downloads takes most of that. This tells OpenTofu to keep its plugins in `/tmp` (16 GB) instead, and remembers the setting for future sessions:

```bash
echo 'export TF_DATA_DIR=/tmp/tofu-data' >> ~/.bashrc
export TF_DATA_DIR=/tmp/tofu-data
```

`/tmp` is wiped when CloudShell restarts. If a later `tofu` command says the plugins are missing, run `tofu init` again (about 30 seconds). Your state file stays safe in `infra/`.

### 4. Create the infrastructure

```bash
cd infra
tofu init
```

You should see `OpenTofu has been successfully initialized!`

```bash
tofu plan
tofu apply
```

`tofu plan` lists everything that will be created. `tofu apply` shows the same list and asks for confirmation: type `yes`.

_Next steps (SNS, Lambdas, EventBridge, Amplify, Cognito, API Gateway) coming soon._

## Demo

_Coming soon._

## Cleanup

_Coming soon._

## Troubleshooting

**`tofu init` fails with `no space left on device`**
CloudShell's home folder (1 GB) is full. You skipped step 3, or you're in a new shell where it isn't set. Fix:

```bash
rm -rf .terraform
export TF_DATA_DIR=/tmp/tofu-data
tofu init
```

To see what is using your home folder: `du -sh ~/* ~/.[!.]* 2>/dev/null | sort -h | tail`. Old lab projects are often the cause.

**`tofu apply` fails with `s3:GetBucketObjectLockConfiguration ... explicit deny in a service control policy`**
Learner Lab blocks that call, and OpenTofu's standard `aws_s3_bucket` resource always makes it. This repo already works around it (`infra/s3.tf` creates the bucket with the AWS CLI), so you should only see this if you add an `aws_s3_bucket` resource yourself.
