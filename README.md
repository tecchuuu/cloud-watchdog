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

Save the email address alerts should go to (replace `you@gmail.com`). This file stays on CloudShell and is never committed:

```bash
cd infra
echo 'alert_email = "you@gmail.com"' > terraform.tfvars
tofu init
```

You should see `OpenTofu has been successfully initialized!`

```bash
tofu plan
tofu apply
```

`tofu plan` lists everything that will be created. `tofu apply` shows the same list and asks for confirmation: type `yes`.

You should see `Apply complete!` and a list of outputs. **Copy `dashboard_url`** somewhere: you need it for Cognito in step 8. (Read the outputs again any time with `tofu output`.) In the console you can now find:

| Service | Where to look | What's there |
|---|---|---|
| DynamoDB | Tables | `watchdog_findings`, `watchdog_actions` |
| S3 | Buckets | `watchdog-reports-<account-id>` |
| Lambda | Functions | `watchdog-scanner`, `watchdog-actions` |
| EventBridge | Rules | `watchdog-daily-scan` (runs once a day) |
| SNS | Topics | `watchdog-alerts` |
| CloudWatch | Alarms | `watchdog-scanner-errors` |
| Amplify | All apps | `watchdog-dashboard` (empty until step 10) |

### 5. Confirm the alert email

AWS sends an email titled **AWS Notification - Subscription Confirmation** to the address from step 4. Click **Confirm subscription**. Until you do, no alerts arrive (check spam if you don't see it).

### 6. Test the scanner

The scanner runs once a day on its own. To run it now, plant some test problems ([Test scripts](#test-scripts)) and call the Lambda by hand:

```bash
cd ~/cloud-watchdog
bash scripts/plant-mess.sh
aws lambda invoke --function-name watchdog-scanner --cli-read-timeout 150 /tmp/out.json
cat /tmp/out.json
```

You should see `"StatusCode": 200`, then a summary with `"grade": "F"`, `"new": 4` and `"errors": []`. Within a minute an email **Cloud Watchdog: 4 new issue(s)** arrives. Its logs are in **CloudWatch → Log groups → /aws/lambda/watchdog-scanner**.

Leave the mess planted for step 7.

### 7. Test the actions Lambda

`watchdog-actions` does Fix / Delete / Ignore and answers the dashboard. Before API Gateway exists, `scripts/invoke-actions.sh` calls it the way API Gateway will:

```bash
bash scripts/invoke-actions.sh "GET /findings"
bash scripts/invoke-actions.sh "POST /fix" '{"finding_ids":["<a finding_id from the list>"]}'
bash scripts/invoke-actions.sh "GET /verify-log"
```

You should see `HTTP 200` each time, the fix result `"OK"`, and `"ok": true` from the log check.

Clean up with `bash scripts/clean-mess.sh`.

### 8. Cognito: the login (by hand)

Cognito keeps the list of people allowed into the dashboard and runs the login page. You set it up in the console so you see every piece.

You need your `dashboard_url` from step 4 (`cd ~/cloud-watchdog/infra && tofu output dashboard_url`).

**Create the user pool and app client**

1. Console → **Cognito** → **User pools** → **Create user pool**.
2. **Application type:** **Single-page application (SPA)**. The dashboard is plain JavaScript in the browser, so it can't keep a secret; this type gives an app client with no secret, using the "code + PKCE" login.
3. **Name your application:** `watchdog-dashboard`
4. **Options for sign-in identifiers:** tick **Username** only. (Watchdog writes this username into the audit log. With email-only sign-in it would be a random ID.)
5. **Self-registration:** leave it **off**. Only you create accounts; strangers can't sign up.
   **Required attributes for sign-up:** choose **email** (Cognito insists on email or phone when you sign in with a username). These two choices can't be changed later.
6. **Return URL:** paste your `dashboard_url`, e.g. `https://main.xxxxxxxx.amplifyapp.com/` (with the `/` at the end).
7. **Create user directory**.

**Allow the sign-out URL**

8. In the new pool: **Applications → App clients → watchdog-dashboard → Login pages** tab → **Edit**.
9. Check **Allowed callback URLs** has your `dashboard_url`. Under **Allowed sign-out URLs**, add the same `dashboard_url`.
10. Check **OAuth grant types** has **Authorization code grant**, and **OpenID Connect scopes** has **OpenID** and **Email**. **Save changes**.

**Create your user**

11. **User management → Users → Create user**.
12. Choose **Don't send an invitation**. Type a **User name** (e.g. your name; it shows up in the audit log) and your **Email address**, tick **Mark email address as verified**, choose **Set a password** and type a temporary password. **Create user**.

The first time you log in, Cognito asks you to choose a new password.

**Write these down** (you need them in steps 9 and 10):

| What | Where | Looks like |
|---|---|---|
| User pool ID | Pool **Overview** | `us-east-1_AbCdEf123` |
| Client ID | **App clients** list | `1h57kf5cpq17m0eml12EXAMPLE` |
| Cognito domain | **Branding → Domain** | `https://us-east-1abcdef.auth.us-east-1.amazoncognito.com` |

_Next steps (API Gateway, dashboard) coming soon._

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
