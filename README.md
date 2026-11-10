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
├── infra/      OpenTofu, one file per service: s3, dynamodb, sns, lambda,
│               eventbridge, alarm, amplify (+ providers, variables, outputs)
├── lambda/     scanner.py (finds problems), actions.py (Fix/Delete/Ignore + API)
├── web/        dashboard: index.html, auth.js (login), app.js, style.css
├── scripts/    plant-mess.sh, clean-mess.sh   fake problems to find, and remove
│               deploy-web.sh                  upload the dashboard to Amplify
│               reset-demo.sh                  wipe findings/log/history for a demo
│               invoke-actions.sh              call the API Lambda without a browser
└── docs/       architecture.tex/.pdf (diagram), console-settings.md (every hand-typed
                value explained), dashboard-design.md (why the dashboard looks the way
                it does), demo-script.md (video + live demo)
```

## Setup and deploy

Steps 1–7 use OpenTofu and scripts; steps 8–9 are done by hand in the console; step 10 uploads the dashboard. About 30 minutes.

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

You should see `"StatusCode": 200`, then a summary with `"grade": "F"`, `"new": 4` and `"errors": []`. Within a minute an email **Cloud Watchdog: 4 new finding(s)** arrives. Its logs are in **CloudWatch → Log groups → /aws/lambda/watchdog-scanner**.

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

Cognito keeps the list of people allowed into the dashboard and runs the login page. You set it up in the console so you see every piece. Why each value is what it is: [docs/console-settings.md](docs/console-settings.md).

You need your `dashboard_url` from step 4 (`cd ~/cloud-watchdog/infra && tofu output dashboard_url`).

**Create the user pool and app client**

1. Console → **Cognito** → **User pools** → **Create user pool**.
2. **Application type:** **Single-page application (SPA)**. The dashboard is plain JavaScript in the browser, so it can't keep a secret; this type gives an app client with no secret, using the "code + PKCE" login.
3. **Name your application:** `watchdog-dashboard`
4. **Options for sign-in identifiers:** tick **Username** only. (Watchdog writes this username into the audit log. With email-only sign-in it would be a random ID.)
5. **Self-registration:** leave it **off**. Only you create accounts; strangers can't sign up.
   **Required attributes for sign-up:** choose **email** (Cognito insists on email or phone when you sign in with a username). These two choices can't be changed later.
6. **Return URL:** paste your `dashboard_url`, e.g. `https://main.xxxxxxxx.amplifyapp.com/` (with the `/` at the end).
7. **Create user directory**. Cognito names the pool for you (e.g. `User pool - abc123`) and shows a **Quick setup guide** with React/Angular sample code. Skip it: the dashboard has its own login code.

**Allow the sign-out URL**

8. Menu (☰, top left) → **User pools** → your new pool → **Applications → App clients → watchdog-dashboard → Login pages** tab → **Edit**.
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

### 9. API Gateway: the dashboard's door to Lambda (by hand)

API Gateway gives `watchdog-actions` a public https:// address. Before any request reaches the Lambda, it checks the Cognito login token; requests without a valid token get `401 Unauthorized` and never run your code.

**Create the API and connect it to Lambda**

1. Console → **API Gateway** → **Create API** → **HTTP API** → **Build**.
2. **Integrations → Add integration** → **Lambda**, region **us-east-1**, function **watchdog-actions**. Version **2.0**.
3. **API name:** `watchdog-api` → **Next**.
4. **Configure routes:** add these 8 routes, every one with target **watchdog-actions**. Pick the method from the dropdown; the path box gets only the path (`/findings`, not `GET /findings`):

   | Method | Resource path |
   |---|---|
   | GET | `/findings` |
   | GET | `/report` |
   | GET | `/verify-log` |
   | POST | `/scan` |
   | POST | `/preview` |
   | POST | `/fix` |
   | POST | `/delete` |
   | POST | `/ignore` |

   → **Next**.
5. **Stages:** keep `$default` with **Auto-deploy** on → **Next** → **Create**.

The console also gives API Gateway permission to call the Lambda (you can see it in **Lambda → watchdog-actions → Configuration → Permissions**).

**Require a login on every route**

6. Left menu **Authorization** → **Manage authorizers** tab → **Create**.
   - Type **JWT**, name `cognito`
   - Identity source: `$request.header.Authorization` (the default)
   - **Issuer URL:** `https://cognito-idp.us-east-1.amazonaws.com/<your user pool ID>`
   - **Audience:** your **Client ID** → **Create**.
7. **Attach authorizers to routes** tab: click each of the 8 routes, pick `cognito`, **Attach authorizer**. Every route should show a **JWT** badge.

**Let the dashboard call it from the browser (CORS)**

8. Left menu **CORS** → **Configure**:
   - **Access-Control-Allow-Origin:** your `dashboard_url` **without** the `/` at the end, e.g. `https://main.xxxxxxxx.amplifyapp.com` (type it, then **Add**)
   - **Access-Control-Allow-Headers:** `authorization`, `content-type`
   - **Access-Control-Allow-Methods:** `GET`, `POST`
   - **Save**.

Browsers block a page from calling another site unless that site says it's allowed; this is where the API says "the dashboard may call me".

**Write down** the **Invoke URL** from the API's **Overview** page (`https://abc123.execute-api.us-east-1.amazonaws.com`).

**Test that the door is locked:**

```bash
curl -i https://<your invoke URL>/report
```

You should see `HTTP/2 401` and `{"message":"Unauthorized"}`: no token, no entry. With a token it works; the dashboard in step 10 sends one.

### 10. Upload the dashboard

```bash
cd ~/cloud-watchdog
bash scripts/deploy-web.sh
```

It asks for the three values you wrote down: the **API Gateway Invoke URL** (step 9), the **Cognito domain** and the **client ID** (step 8). It remembers them, so next time you just press Enter. Then it writes `web/config.js`, zips `web/` and uploads it to Amplify.

You should see `Done. Open https://main.xxxxxxxx.amplifyapp.com/`. Open it:

1. You land on Cognito's login page. Log in with the user from step 8 and choose a new password.
2. You come back to the dashboard with your username at the top right.
3. If the mess from step 6 is still planted, press **Scan now**, then try **Fix**, **Ignore** and the **Report** tab. Otherwise run `bash scripts/plant-mess.sh` first.

Run `deploy-web.sh` again whenever you change anything in `web/`.

**The three buttons**

| Button | What it does | Can you undo it? |
|---|---|---|
| **Fix** | Removes the risk but keeps the resource (closes the open port, blocks public access, snapshots then removes a loose volume). You see a preview first. | Mostly: the audit log keeps what was changed |
| **Delete** | Removes the resource for good. Asks you to confirm. | No |
| **Ignore** | Tags the resource `watchdog-ignore=true` with your reason. Scans skip it. | Yes: remove that tag from the resource in the AWS console, and it comes back as a finding on the next scan |

Under each resource name the dashboard shows its AWS ID (`sg-…`, `vol-…`): paste that into the console's search box to find it. Why the dashboard looks and behaves the way it does: [docs/dashboard-design.md](docs/dashboard-design.md).

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

Scan once more: the planted problems are now `FIXED`, and the summary shows the dollars saved. Both scripts are safe to run more than once: `plant-mess.sh` reuses test resources that already exist instead of making duplicates.

## Demo

About 5 minutes: plant the mess, find it, fix it, prove it's gone.

**The day before** (optional, for the 5th check): launch the idle EC2. It needs hours of CPU history before it counts as idle, like a real forgotten server. To flag it after 2 hours instead of 24:

```bash
bash scripts/plant-mess.sh --ec2
cd infra && tofu apply -var idle_hours=2 && cd ..
```

**Right before** — start from a clean slate so "$ saved", history and the log show only the demo:

```bash
bash scripts/reset-demo.sh
```

**The demo:**

1. Open the dashboard: no findings (or 1, the idle EC2).
2. Run `bash scripts/plant-mess.sh`: 4 problems in seconds (Elastic IP, open SSH, public bucket, loose volume).
3. **Scan now** → the findings with cost per month, risk and CIS labels (hover a label for the plain-English rule).
4. **Delete** one by hand → red confirm popup → Delete.
5. **Fix all** → preview of every change → Fix.
6. **Scan now** → 0 findings, grade F → A.
7. **Report** tab: $ saved, the audit log with your username, **Verify log** → intact.
8. Show the SNS email and the EventBridge rule `watchdog-daily-scan`.

Backup if a fix fails: `bash scripts/clean-mess.sh`.

## Cleanup

Removes everything, as if it was never installed. Do the hand-made parts first, then let OpenTofu remove the rest.

1. **Test resources:** `bash scripts/clean-mess.sh`
2. **API Gateway:** console → API Gateway → `watchdog-api` → **Delete**.
3. **Cognito:** console → Cognito → your user pool → **Delete user pool**. If it refuses, first turn off **Deletion protection** (pool **Settings**), and delete the domain under **Branding → Domain**.
4. **Everything else** (Lambdas, tables, bucket and reports, SNS, schedule, alarm, Amplify):
   ```bash
   cd ~/cloud-watchdog/infra
   tofu destroy
   ```
   Type `yes`. You should see `Destroy complete!`.
5. **Saved dashboard values:** `rm ~/.watchdog-web`

To install again, start from step 4 of [Setup and deploy](#setup-and-deploy). Steps 8–9 give you a new pool ID, client ID, domain and API URL.

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

**`Error: Required plugins are not installed`**
CloudShell was restarted and `/tmp` (where step 3 keeps OpenTofu's plugins) was wiped. Run `tofu init` in `infra/` again. `deploy-web.sh` does this for you.

**The dashboard looks the same after `deploy-web.sh`**
Your browser kept the old files. Hard refresh with **Ctrl+Shift+R** (Mac: Cmd+Shift+R).

**The dashboard shows `Failed to fetch` or a CORS error (F12 → Console)**
API Gateway → CORS → **Access-Control-Allow-Origin** must be your `dashboard_url` exactly, **without** the `/` at the end.

**Cognito says `redirect_mismatch`**
The app client's callback / sign-out URL must be your `dashboard_url` exactly, **with** the `/` at the end (step 8).

**Scan now says it timed out**
API Gateway gives up after 30 seconds, but the scan keeps running in Lambda. Wait a minute and refresh.
