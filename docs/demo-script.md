# Video and demo script

Video: ~5–7 min, due **Nov 16, 11:59 PM**. Live demo: **Nov 17**.
"Show" = what's on screen. "Say" = the one idea to get across, in your own words.

## Before recording

- [ ] Lab started, CloudShell open, `cd ~/cloud-watchdog`
- [ ] Day before (optional): `bash scripts/plant-mess.sh --ec2` and `cd infra && tofu apply -var idle_hours=2`
- [ ] `bash scripts/reset-demo.sh` → dashboard empty, Report empty
- [ ] Logged in to the dashboard; Gmail open with an old Watchdog email
- [ ] Tabs ready: dashboard, CloudShell, EventBridge rule, `docs/architecture.pdf`

## Video (~6 min)

### 1. Problem (30 s)
**Show:** title + the week 9 story.
**Say:** In week 9 of this course, 5 forgotten Elastic IPs were still allocated: about $18 a month for nothing. Forgotten resources cost money, and open ports or public buckets are security holes. Small teams don't have a cloud security person to catch them.

### 2. Architecture (1 min)
**Show:** `docs/architecture.pdf`, follow the numbered arrows.
**Say:**
- 8 services, serverless: no server to run, pay per use, about $0 when idle.
- Daily path: EventBridge → scanner Lambda → reads the account (read only) → DynamoDB + S3 report → SNS email.
- Dashboard path: Amplify serves the page → Cognito login → API Gateway checks the token on every request → actions Lambda.
- "Cognito proves who you are, API Gateway checks that proof every time, and the Lambda only sees requests that passed."
- Orange dashed boxes were set up by hand, the rest with OpenTofu.

### 3. Deploy (2 min, speed up the waiting)
**Show:**
1. `tofu apply` → the plan list → `Apply complete!` and the outputs (`dashboard_url`).
2. Cognito: create pool (SPA, Username sign-in, no self sign-up, return URL = dashboard URL).
3. API Gateway: routes (GET reads, POST acts), JWT authorizer (issuer = pool, audience = client ID), CORS.
4. `curl …/report` → **401**: the door is locked without a token.
5. `bash scripts/deploy-web.sh` → `Done`.

**Say:** One file per service in `infra/`. The services only work together because values are copied between them (the table at the top of `docs/console-settings.md`): dashboard URL → Cognito and CORS, pool ID → issuer, client ID → audience.

### 4. Demo (2–3 min)
Same steps as the live demo below, steps 2–7.

### 5. Limitations and future work (30 s)
**Say** (pick 3–4):
- One AWS account only: scanning many needs cross-account roles, which Learner Lab blocks.
- Costs are estimates from a price list, not the real bill.
- Runs on LabRole, which has more permissions than it needs. Future: least-privilege role.
- Daily, not real time. Future: EventBridge + CloudTrail.
- The log is tamper-evident, not tamper-proof. Future: S3 Object Lock.
- Delete can't be undone (that's why Fix exists and Delete asks to confirm).

## Live demo (4–5 min)

1. **Dashboard:** empty (or 1 finding: the idle EC2). Point at "Last scan: X ago".
2. **CloudShell:** `bash scripts/plant-mess.sh` → name each of the 4 as it appears.
3. **Scan now** (counter runs) → findings with cost per month, risk, CIS label. Hover a CIS label.
4. **Delete** the volume → red popup "can't be undone" → Delete → result OK.
5. **Fix all** → preview says exactly what changes ("keep the group, remove the rule") → Fix → all OK.
6. **Scan now** → 0 findings, grade **F → A**.
7. **Report:** $ saved, history bars, audit log with **your username** (from the login token, not the browser), **Verify log** → intact.
   Optional (20 s): edit one log entry in DynamoDB → Verify → "broken at #N" → change it back.
8. **Gmail:** the alert email. **EventBridge:** rule `watchdog-daily-scan`, `rate(1 day)`.

Backup if a fix fails: `bash scripts/clean-mess.sh`. Backup if AWS is down: the video.

## Likely questions

| Question | Short answer |
|---|---|
| Why API Gateway if Cognito already logs you in? | Cognito hands out the token once; API Gateway checks it on every request before the Lambda runs. |
| Why can't the username be faked? | It's read from the token after API Gateway verified its signature, never from the request body. |
| What does the hash chain prove? | Each entry includes the previous entry's hash, so changing any old entry breaks every hash after it; Verify finds the first break. |
| Why not `tofu destroy` to reset the demo? | It would make a new Amplify URL, and Cognito + CORS point at the old one. `reset-demo.sh` only empties the data. |
| Why serverless? | Nothing to patch or keep running, scales by itself, close to $0 when idle. The cost: more pieces to connect. |
| Why Fix and Delete? | Fix removes the risk but keeps the resource (reversible); Delete removes it for good. |
| Is the token stored safely? | sessionStorage (gone when the tab closes), 60-minute ID token, refresh token revoked on logout, PKCE instead of a client secret. |
| How do you undo an Ignore? | Remove the `watchdog-ignore` tag from the resource in the console; the next scan shows it as OPEN again. A button for it is future work. |
| Why does the dashboard look so plain? | It's a work tool: colour is only used for meaning (risk, good, clickable), every action has a preview, and text contrast was measured. See `docs/dashboard-design.md`. |
| Why does the idle EC2 need a day? | Idle = low CPU over hours of CloudWatch data; a just-launched instance has no history yet. |
