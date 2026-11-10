// auth.js — logging in with Cognito (authorization code + PKCE).
//
// 1. login(): make a random secret (the "verifier"), keep it in this tab,
//    and send its SHA-256 (the "challenge") to Cognito's login page.
// 2. Cognito checks the password and sends the browser back to the
//    dashboard with ?code=... in the URL.
// 3. handleRedirect(): swap the code + the original verifier for tokens.
//    Someone who steals the code can't use it without the verifier,
//    which never left this tab. That's what replaces a client secret.
//
// Tokens live in sessionStorage: gone when the tab closes.
// The ID token (60 min) goes with every API call; when it's about to
// expire, the refresh token quietly gets a new one.

const AUTH_KEYS = ["id_token", "refresh_token", "expires_at", "pkce_verifier", "pkce_state"];

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256(text) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
}

// Step 1: go to Cognito's login page
async function login() {
  const verifier = randomString();
  const state = randomString(); // checked on the way back, so nobody can slip us their own code
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("pkce_state", state);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: "openid email",
    code_challenge_method: "S256",
    code_challenge: base64url(await sha256(verifier)),
    state,
  });
  location.assign(`${CONFIG.cognitoDomain}/oauth2/authorize?${params}`);
}

// Ask Cognito's token endpoint for tokens (used for the first login and for refresh)
async function tokenRequest(fields) {
  const resp = await fetch(`${CONFIG.cognitoDomain}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CONFIG.clientId, ...fields }),
  });
  if (!resp.ok) throw new Error(`token request failed (${resp.status})`);
  const t = await resp.json();
  sessionStorage.setItem("id_token", t.id_token);
  sessionStorage.setItem("expires_at", String(Date.now() + t.expires_in * 1000));
  if (t.refresh_token) sessionStorage.setItem("refresh_token", t.refresh_token);
}

// Step 3: back from Cognito with ?code=... ?
async function handleRedirect() {
  const url = new URL(location.href);
  const code = url.searchParams.get("code");
  if (!code) return;
  history.replaceState(null, "", url.pathname); // remove ?code= from the address bar

  if (url.searchParams.get("state") !== sessionStorage.getItem("pkce_state")) {
    throw new Error("login state didn't match; please log in again");
  }
  await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: CONFIG.redirectUri,
    code_verifier: sessionStorage.getItem("pkce_verifier"),
  });
  sessionStorage.removeItem("pkce_verifier");
  sessionStorage.removeItem("pkce_state");
}

// Get new ID token with the refresh token. Returns false if that's not possible.
async function refresh() {
  const refreshToken = sessionStorage.getItem("refresh_token");
  if (!refreshToken) return false;
  try {
    await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    return true;
  } catch {
    return false;
  }
}

// A valid ID token, refreshed if it expires within a minute. null = must log in.
async function getToken() {
  if (!sessionStorage.getItem("id_token")) return null;
  const expiresAt = Number(sessionStorage.getItem("expires_at") || 0);
  if (Date.now() > expiresAt - 60_000 && !(await refresh())) return null;
  return sessionStorage.getItem("id_token");
}

// The username inside the ID token (only for showing it; the API reads
// it again from the token after API Gateway has checked the signature).
function currentUser() {
  const token = sessionStorage.getItem("id_token");
  if (!token) return "";
  const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  return payload["cognito:username"] || payload.email || "";
}

// Log out: cancel the refresh token at Cognito, forget everything, end Cognito's session
async function logout() {
  const refreshToken = sessionStorage.getItem("refresh_token");
  if (refreshToken) {
    await fetch(`${CONFIG.cognitoDomain}/oauth2/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshToken, client_id: CONFIG.clientId }),
    }).catch(() => {});
  }
  AUTH_KEYS.forEach((k) => sessionStorage.removeItem(k));
  const params = new URLSearchParams({ client_id: CONFIG.clientId, logout_uri: CONFIG.redirectUri });
  location.assign(`${CONFIG.cognitoDomain}/logout?${params}`);
}
