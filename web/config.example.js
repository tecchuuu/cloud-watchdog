// Example only. scripts/deploy-web.sh writes the real web/config.js
// (git-ignored) with your own values from README steps 8-9.
window.CONFIG = {
  apiUrl: "https://abc123.execute-api.us-east-1.amazonaws.com",          // API Gateway Invoke URL
  cognitoDomain: "https://us-east-1abc123.auth.us-east-1.amazoncognito.com", // Cognito domain
  clientId: "1h57kf5cpq17m0eml12EXAMPLE",                                // Cognito app client ID
  redirectUri: "https://main.xxxxxxxx.amplifyapp.com/",                  // dashboard_url
};
