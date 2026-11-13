# How Cloud Watchdog is set up

A plain-words guide to every service: what it does, what we set, and why.
Read this instead of the scripts. Each section ends with a line you can say out loud.

For the two services set up by hand (Cognito, API Gateway), every typed value is explained in
[console-settings.md](console-settings.md). This file covers the rest and how the pieces fit.

## The big picture

There are two separate pieces, joined by one URL.

| Piece | Services | Works on its own? |
|---|---|---|
| **The scanner** | EventBridge, Lambda (scanner), DynamoDB, S3, SNS | Yes. After `tofu apply` it scans daily and emails you. |
| **The dashboard** | Amplify, Cognito, API Gateway, Lambda (actions) | No. It needs the scanner's table to have something to show. |

- OpenTofu creates **16 resources** across 6 services (plus CloudWatch for logs and an alarm).
- Cognito and API Gateway are made **by hand**, because they were not covered in class.
- The dashboard is a **static front end**: four files with no server of their own. The back end is
  **serverless**: API Gateway and Lambda run only when a request arrives.

> "One command gives me a working scanner. Two services by hand put a dashboard on top of it."

## How a request travels

**The daily scan (no person involved)**

1. EventBridge fires once a day and starts the scanner Lambda.
2. The scanner reads the account (read-only calls) in us-east-1 and us-west-2.
3. It compares the result with the last scan stored in DynamoDB.
4. It saves the findings to DynamoDB and a full JSON report to S3.
5. If there is anything **new**, it publishes to SNS, which emails you.

**Opening the dashboard**

1. The browser loads the page files from Amplify. Amplify's job ends there.
2. The page sends you to Cognito's login page. Cognito gives the browser a signed token.
3. The page asks API Gateway for `GET /findings`, with the token.
4. API Gateway checks the token, then runs the actions Lambda.
5. The Lambda reads DynamoDB and returns JSON. The answer goes back the same way.
6. The page turns the JSON into the table and the grade.

**Clicking a button** is the same path with a different route: `POST /scan`, `/fix`, `/delete`, `/ignore`.

> "Cognito is the front desk that gives me a badge. API Gateway is the guard who checks the badge at every door."

---

## The services OpenTofu creates

Every service has its own file in `infra/`. All resources get two tags automatically:
`managed-by = watchdog` and `project = cloud-watchdog`. The first tag matters: the scanner
**skips anything tagged `managed-by=watchdog`**, so the Watchdog never reports or deletes itself.

### DynamoDB: two tables (`dynamodb.tf`)

| Setting | Value | Why |
|---|---|---|
| Table 1 | `watchdog_findings` | The latest state of every finding. One row per problem. |
| Its key | `finding_id` (text) | Looks like `unused_eip#us-east-1#eipalloc-0a6f…`: check, region, resource. The same problem always gets the same ID, so the next scan can recognise it. |
| Table 2 | `watchdog_actions` | The audit log: who clicked what, when, and the result. |
| Its keys | `pk` (text) + `seq` (number) | `seq` counts 1, 2, 3… so the log is read back in order. |
| Billing | `PAY_PER_REQUEST` | Pay per read and write, nothing when idle. No capacity to plan. |

> "One table is the current state, the other is the history of actions. Both cost nothing when nobody uses them."

### S3: the report bucket (`s3.tf`)

| Setting | Value | Why |
|---|---|---|
| Name | `watchdog-reports-<account-id>` | Bucket names are global, so the account ID makes it unique. |
| Public access | All four "Block Public Access" switches on | The reports list your weaknesses. They must never be public. |
| Contents | `reports/YYYY/MM/DD/<time>.json` | One full report per scan. The Report tab's history chart reads the last 30. |

**Why it is not a normal `aws_s3_bucket` resource:** the Learner Lab blocks one API call that
OpenTofu's S3 resource always makes (`GetBucketObjectLockConfiguration`). So this file runs three
AWS CLI commands instead: create the bucket, block public access, tag it. On `tofu destroy` it
empties and removes the bucket.

> "DynamoDB holds what is true now. S3 keeps a dated copy of every scan."

### SNS: the email (`sns.tf`)

| Setting | Value | Why |
|---|---|---|
| Topic | `watchdog-alerts` | One place both alerts go to. |
| Subscription | protocol `email`, address = your `alert_email` | AWS first sends a confirmation email. Until you click it, nothing is delivered. This stops people using SNS to spam others. |

Two things publish to this topic: the scanner (new findings) and the CloudWatch alarm (scanner failed).

> "SNS is the mailman. The scanner and the alarm both hand it letters."

### Lambda: the two functions (`lambda.tf`)

Both functions come from the same zip of the `lambda/` folder. OpenTofu zips it for you and
re-uploads only when the code changes.

| Setting | `watchdog-scanner` | `watchdog-actions` | Why |
|---|---|---|---|
| Starts at | `scanner.lambda_handler` | `actions.lambda_handler` | File name, then function name. |
| Runtime | Python 3.12 | Python 3.12 | boto3 (the AWS library) is built in, so there is nothing to install. |
| Timeout | 120 s | 30 s | The scan checks two regions. API Gateway gives up after 30 s anyway. |
| Memory | 256 MB | 256 MB | Plenty for API calls. |
| Role | `LabRole` | `LabRole` | The only role a Learner Lab allows. A real account would use a smaller role for each. |
| Retries | 0 | (default) | A failed daily scan is not run again twice. One failure, one alarm. |
| Logs | kept 14 days | kept 14 days | In CloudWatch, `/aws/lambda/<name>`. |

**Environment variables** are how OpenTofu wires the services together. The code never contains a
table name or an ARN; it reads them from these:

| Variable | Given to | Value |
|---|---|---|
| `REGIONS` | both | `us-east-1,us-west-2` |
| `FINDINGS_TABLE` | both | the findings table's name |
| `REPORTS_BUCKET` | both | the bucket's name |
| `SNS_TOPIC_ARN` | scanner | the topic to publish to |
| `IDLE_HOURS`, `IDLE_CPU_PERCENT` | scanner | 24 and 5: the "idle server" rule |
| `ACTIONS_TABLE` | actions | the audit log table's name |
| `SCANNER_FUNCTION_NAME` | actions | so **Scan now** knows which Lambda to start |

> "The scanner only looks. The actions function is the only one that changes anything, and only when a logged-in person asks."

### EventBridge: the schedule (`eventbridge.tf`)

| Resource | Value | Why |
|---|---|---|
| Rule | `watchdog-daily-scan`, schedule `rate(1 day)` | Fires every 24 hours, counted from when the rule was created. |
| Target | the scanner Lambda | What the rule starts. |
| Permission | lets `events.amazonaws.com` invoke the scanner, **only from this rule** | Without it, EventBridge is not allowed to call the Lambda. |

> "EventBridge is the alarm clock. It does nothing but start the scanner once a day."

### CloudWatch: logs and one alarm (`alarm.tf`)

| Setting | Value | Why |
|---|---|---|
| Alarm | `watchdog-scanner-errors` | Tells you when the scanner itself breaks. |
| Watches | Lambda metric `Errors` for the scanner | AWS counts failed runs for you. |
| Rule | 1 or more errors in 1 day | One failure is enough. |
| No data | counts as "fine" | No runs today is not an error. |
| Action | publish to the SNS topic | So the failure arrives as an email. |

The scanner helps this work: if any check fails, it **still saves what it found**, then ends with an
error on purpose, so the alarm fires. This was seen for real: with the lab off, the daily scan
failed and the alarm email arrived.

> "A scanner that fails silently is worse than no scanner. This alarm is how it tells me."

### Amplify: the host (`amplify.tf`)

| Setting | Value | Why |
|---|---|---|
| App | `watchdog-dashboard`, platform `WEB` | Plain static files, no server code, no build step. |
| Branch | `main`, stage `PRODUCTION` | Gives the address `https://main.<id>.amplifyapp.com/`. |

OpenTofu creates an **empty** host. `scripts/deploy-web.sh` fills it: it writes `web/config.js`
(the API address, the Cognito domain, the client ID), zips `web/`, and uploads it.

> "Amplify only hands out four files. Every number on the page comes from the API."

---

## The two services set up by hand

Full values are in [console-settings.md](console-settings.md). The short version:

**Cognito** keeps the list of users and runs the login page.

- App type **SPA**: the page runs in the browser, so it cannot keep a secret. It uses "code + PKCE" instead.
- Sign-in with a **username**, so the audit log shows a readable name.
- **Self-registration off**: only the admin creates accounts.
- The **callback and sign-out URLs** are the dashboard address, so a fake site cannot receive your login.
- Tokens last **60 minutes**; a refresh token keeps you in for up to **5 days**.

**API Gateway** gives the actions Lambda a public https address and guards it.

- **8 routes**, all pointing to `watchdog-actions`. `GET` routes read, `POST` routes change something.
- A **JWT authorizer** named `cognito` on every route. It checks three things on each request:
  who signed the token (**issuer** = your user pool), who it was made for (**audience** = your client ID), and that it has not expired.
- **CORS** allows only the dashboard's address to call the API from a browser.
- No token → `401 Unauthorized`, and the Lambda never runs.

**Which value goes where**

| Value | Comes from | Goes into |
|---|---|---|
| `dashboard_url` | `tofu apply` output | Cognito callback + sign-out URL (with `/`), API Gateway CORS origin (without `/`) |
| User pool ID | Cognito → Overview | End of the authorizer's Issuer URL |
| Client ID | Cognito → App clients | Authorizer's Audience, and `deploy-web.sh` |
| Cognito domain | Cognito → Branding → Domain | `deploy-web.sh` |
| Invoke URL | API Gateway → Stages → $default | `deploy-web.sh` |

---

## What the scanner does (`lambda/scanner.py`)

### The five checks

| # | Check | It looks for | Risk | CIS rule |
|---|---|---|---|---|
| 1 | Unused Elastic IP | A public IP not attached to anything (about $3.65 a month) | LOW | none |
| 2 | Open admin ports | A security group that lets the whole internet reach SSH (22), RDP (3389) or MySQL (3306) | HIGH | 5.2 (IPv4), 5.3 (IPv6) |
| 3 | Public S3 bucket | A bucket anyone can read, through its policy or its ACL | HIGH | 2.1.4 |
| 4 | Unattached EBS volume | A disk not attached to any server | LOW | none |
| 5 | Idle EC2 | A server running 24 h or more whose CPU never reached 5% | LOW | none |

- A cost finding of **$20 a month or more** becomes MEDIUM.
- Costs are **estimates** from a small price list in the code, not the real bill.
- Every check **skips** resources tagged `managed-by=watchdog` (the app itself) or `watchdog-ignore=true` (you pressed Ignore).
- Adding a check means writing one more function and adding it to a list.

### The status of a finding

| Status | Meaning |
|---|---|
| **NEW** | Found for the first time (or it came back after being fixed). These are emailed. |
| **OPEN** | It was there last scan and it is still there. |
| **FIXED** | It was there last scan and now it is gone. |
| **IGNORED** | You pressed Ignore. Remove the tag and the next scan shows it as OPEN again. |

This "memory" is why the email is not spam: you are told about a problem **once**, when it is new.
On Mondays, the scheduled run also sends one reminder listing anything left OPEN for 7 days or more.

### The grade

Start at 100. Each open finding costs points: **HIGH 25, MEDIUM 10, LOW 5**.
A is 90 or more, B 80, C 70, D 60, F below 60.
The four test problems are 2 HIGH + 2 LOW = 100 − 50 − 10 = **40, an F**.

> "The scanner is read-only. It finds five kinds of problems, remembers what it saw last time, and only emails what is new."

---

## What the buttons do (`lambda/actions.py`)

### Every action follows the same six steps

1. **Look up the finding** in DynamoDB. The resource to change comes from there, never from the browser's request.
2. **Check the resource again** in AWS. If it is already gone or fine, the result is `ALREADY_FIXED` and nothing is touched.
3. **Safety rules**: refuse anything tagged `managed-by=watchdog` or `watchdog-ignore=true`.
4. **Do it.**
5. **Write an audit log entry**: user, action, finding, result, time.
6. **Update the finding's status.**

### What Fix and Delete mean for each check

| Check | Fix (keeps the resource) | Delete (removes it) |
|---|---|---|
| Unused Elastic IP | Release the IP | Release the IP |
| Open admin ports | Remove only the rules that open the port to the world | Delete the security group |
| Public bucket | Turn on Block Public Access | Delete the bucket |
| Unattached volume | Take a snapshot, then remove the volume | Remove the volume, no snapshot |
| Idle EC2 | Stop the server | Terminate the server |

**Ignore** tags the resource `watchdog-ignore=true` and saves your reason. It needs a reason.

The dashboard always shows a **preview** first (`POST /preview`): the exact change, before anything happens.

### The audit log and "Verify log"

- Each entry stores a **hash** (a fingerprint) of its own content **and** the hash of the entry before it.
- Change any old entry and its fingerprint no longer matches, and neither does every entry after it.
- **Verify log** walks the chain from entry 1 and reports the first break.
- It is **tamper-evident, not tamper-proof**: it shows that someone changed the log, it cannot stop them.

**Who clicked** comes from the login token that API Gateway already checked (`cognito:username`),
not from anything the browser sends, so a user cannot pretend to be someone else.

> "Every change is previewed, re-checked, and written to a log that shows if anyone edits it later."

---

## The scripts

| Script | What it does |
|---|---|
| `plant-mess.sh` | Creates the 4 fake problems (add `--ec2` for the idle server). Safe to run twice. |
| `clean-mess.sh` | Removes everything tagged `watchdog-test=true`. |
| `deploy-web.sh` | Asks for the Invoke URL, Cognito domain and client ID; uploads the dashboard to Amplify. |
| `reset-demo.sh` | Empties both tables and the reports, for a clean demo. Asks you to type RESET. |
| `invoke-actions.sh` | Calls the actions Lambda without a browser, for testing before API Gateway exists. |

## Limits worth knowing

- **Learner Lab:** the Lambdas only run while a lab session is started. In a normal account it runs all day.
- **One role:** everything uses `LabRole`. A real deployment would give each Lambda only what it needs.
- **One account, two regions.** More regions are one setting; more accounts need cross-account roles.
- **Once a day, not real time.** A problem can exist for up to 24 hours before the scan sees it.
- **Estimated costs**, not the bill.
