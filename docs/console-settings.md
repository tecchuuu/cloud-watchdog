# Console settings explained

Every value typed by hand in README steps 8–9, and why. For the demo and Q&A.

## How the values connect

| Copy from | Paste into |
|---|---|
| `dashboard_url` (`tofu output`) | Cognito callback URL + sign-out URL; API Gateway CORS origin (without the `/` at the end) |
| Cognito **User pool ID** | API Gateway authorizer **Issuer URL** |
| Cognito **Client ID** | API Gateway authorizer **Audience**; `deploy-web.sh` |
| Cognito **domain** | `deploy-web.sh` |
| API Gateway **Invoke URL** | `deploy-web.sh` |

## Cognito (step 8)

| Setting | Value | Why |
|---|---|---|
| Application type | Single-page application (SPA) | The dashboard is JavaScript in the browser; anyone can read its code, so it can't keep a secret. SPA = app client with **no client secret**, login by "authorization code + PKCE" (a one-time random proof instead of a secret). |
| Sign-in identifier | Username | The username goes into the audit log. With email-only sign-in, Cognito's username is a random ID. |
| Self-registration | Off | Only the admin creates accounts. Strangers can't sign up and press Delete. |
| Required attribute | email | Cognito requires email or phone when you sign in with a username. Can't be changed later. |
| Return (callback) URL | `dashboard_url` | After login, Cognito only sends the user back to URLs on this list, so a fake site can't receive the login code. |
| Sign-out URL | `dashboard_url` | Same idea for logging out. |
| OAuth grant type | Authorization code grant | The browser gets a short code, then swaps it for tokens. Safer than tokens in the URL (the old "implicit" grant). |
| Scopes | openid, email | `openid` = give me an ID token (who the user is). `email` = include the email in it. |
| Token lifetimes | ID 60 min, refresh 5 days | The ID token is sent with every request, so if it leaks it's useful for an hour. The refresh token only goes to Cognito, gets new ID tokens quietly, and is revoked on logout. |
| Password policy | Default (8+ chars, upper/lower/number/symbol) | Passwords are not an attribute; Cognito always requires and stores them (hashed). |
| Not used | MFA | Production would turn it on. Skipped to keep the demo short. |

## API Gateway (step 9)

| Setting | Value | Why |
|---|---|---|
| API type | HTTP API | Cheaper and simpler than REST API, and has a built-in JWT authorizer. |
| Integration | Lambda `watchdog-actions`, payload 2.0 | One Lambda handles all 8 routes. 2.0 is the event format `actions.py` reads (`routeKey`, `requestContext.authorizer.jwt.claims`). |
| Routes | 3 GET, 5 POST | **GET reads** (findings, report, verify-log); safe to repeat. **POST acts** (scan, preview, fix, delete, ignore) and carries a JSON body. Names must match `actions.py` exactly, or it answers 404. |
| Stage | `$default`, auto-deploy | One stage, no `/prod` in the URL; changes go live without a separate Deploy click. |

### Authorizer (the guard)

| Setting | Value | Why |
|---|---|---|
| Type | JWT | Cognito's tokens are JWTs; API Gateway checks them itself, no code. (The other type, Lambda, means writing your own check.) |
| Identity source | `$request.header.Authorization` | Where to find the token: the `Authorization:` header the dashboard sends. No header → 401. |
| Issuer URL | `https://cognito-idp.us-east-1.amazonaws.com/<pool ID>` | Who must have signed the token. API Gateway fetches this pool's public keys and checks the signature. Tokens from other pools or made-up ones fail. |
| Audience | Client ID | Which app the token was made for. Blocks tokens from your pool issued to a different app client. |
| Attached to | All 8 routes | A route without the authorizer is open to anyone. |
| Authorization scopes | None | Scopes are an extra check that only works with Cognito *access* tokens. The dashboard sends the *ID* token (it has `cognito:username`), so a scope here would lock it out. |

Checks done on every request, before Lambda runs: signature, audience, expiry. The username from the token is passed to Lambda, which writes it into the audit log; the dashboard can't fake it.

### CORS

Browsers block a page on one site (the Amplify URL) from reading answers from another site (the API) unless the API says it's allowed.

| Setting | Value | Why |
|---|---|---|
| Allow-Origin | `dashboard_url` without the `/` at the end | Only our dashboard may call the API from a browser. Browsers send the origin without a trailing `/`, so one extra character breaks it. |
| Allow-Headers | `authorization`, `content-type` | The two headers the dashboard sends: the token, and "the body is JSON". |
| Allow-Methods | GET, POST | The only methods our routes use. |
| Max-Age | 300 | Before a real request the browser asks "am I allowed?" (a *preflight*). 300 = remember the answer for 5 minutes instead of asking every time. |
| Allow-Credentials | No | We send the token in a header, not as cookies. |

CORS is a browser rule, not security for the API: `curl` ignores it. The authorizer is the real lock.

## Dashboard login (web/auth.js)

| Piece | What it does |
|---|---|
| PKCE verifier | A random secret made in the browser and kept in the tab. Only its SHA-256 (the *challenge*) goes to Cognito. When the browser swaps the login code for tokens, it shows the verifier; a stolen code is useless without it. This replaces a client secret, which a browser app can't keep. |
| state | Another random value, checked when Cognito sends you back, so nobody can slip their own login code into your browser. |
| sessionStorage | Where the tokens live. Cleared when the tab closes, so closing the tab logs you out. |
| Silent refresh | Before the 60-minute ID token runs out, the refresh token gets a new one. You stay logged in while the tab is open (up to 5 days). |
| Logout | Revokes the refresh token at Cognito, clears the tab, and ends Cognito's login session. |
| `Authorization: Bearer <ID token>` | Sent with every API call; that's the header the authorizer's identity source reads. |
| Text escaping | Resource names come from AWS and anyone with access can name a resource `<script>…`. The dashboard always inserts them as text, never as HTML. |
