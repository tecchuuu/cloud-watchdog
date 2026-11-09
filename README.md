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

You should see `Apply complete!` and three outputs: `actions_table`, `findings_table` and `reports_bucket`. In the console you can now find the two tables under **DynamoDB → Tables** and the bucket `watchdog-reports-<account-id>` under **S3**.

_Next steps (SNS, Lambdas, EventBridge, Amplify, Cognito, API Gateway) coming soon._

## Test scripts

Two scripts create and remove fake problems, so you can see the Watchdog find them. Everything they create is tagged `watchdog-test=true`, and nothing else is touched.

**Plant the mess** (from the `cloud-watchdog` folder):

```bash
bash scripts/plant-mess.sh
```

This creates, in us-east-1:

| Problem | Type |
|---|---|
| An Elastic IP not attached to anything | Cost |
| Security group `watchdog-test-open-ssh` with SSH open to `0.0.0.0/0` | Security |
| Public bucket `watchdog-test-public-<account-id>` | Security |
| A 1 GiB EBS volume not attached to anything | Cost |

Add `--ec2` to also launch an idle t3.micro. It only counts as idle after running for `IDLE_HOURS` (24 by default), so for a quick test run the scanner with `IDLE_HOURS=2` and wait 2 hours.

**Run the scanner by hand** (before the Lambda exists). Pointing it at the table and bucket from step 4 lets it remember earlier scans:

```bash
export FINDINGS_TABLE=watchdog_findings
export REPORTS_BUCKET=$(cd infra && tofu output -raw reports_bucket)
python3 lambda/scanner.py
```

The first run shows the 4 planted problems as `NEW` with grade **F (15/100)**. Run it again and they show as `OPEN`. If you have other leftovers in your account (an old `launch-wizard-1` security group is common), they show up too: those are real findings.

**Clean up:**

```bash
bash scripts/clean-mess.sh
```

Scan once more: the planted problems are now `FIXED`, and "Fixed so far" shows the dollars saved. `clean-mess.sh` is safe to run more than once.

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
