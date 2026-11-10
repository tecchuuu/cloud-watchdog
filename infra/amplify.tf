# Amplify Hosting: serves the dashboard (web/ folder) on an https:// URL.
#
# No Git repo is connected. scripts/deploy-web.sh zips web/ and uploads it
# by hand (a "manual deployment"), so this file only makes the empty app
# and its "main" branch. The URL exists right away. It shows an Amplify
# placeholder page until the first upload.
#
# We need the URL before Cognito: Cognito only sends users back to a URL
# it has been told about (the callback URL).

resource "aws_amplify_app" "dashboard" {
  name     = "watchdog-dashboard"
  platform = "WEB" # plain static files (HTML/JS/CSS), no server-side code
}

resource "aws_amplify_branch" "main" {
  app_id      = aws_amplify_app.dashboard.id
  branch_name = "main"
  stage       = "PRODUCTION"
}
