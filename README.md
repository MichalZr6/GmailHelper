# GmailHelper

A small Python utility that automates handling invoice emails:

- Connects to Gmail via Gmail API
- Detects invoice emails
- Downloads or streams PDF attachments
- Uploads them to OneDrive (via rclone)
- Runs automatically every 30 minutes using GitHub Actions

## How it works

1. Gmail API is authorized with OAuth (using `gmail_credentials.json` and `token.json`).
2. Script looks for emails with the invoice label or matching rules.
3. Attachments are sent to OneDrive using `rclone`.
4. GitHub Actions runs the script on a schedule.

## Tech stack

- Python (google-api-python-client, pydantic)
- rclone for OneDrive integration
- GitHub Actions for CI/CD

## Notes

- Secrets (Gmail credentials, tokens, rclone config) are **not** stored in the repo.  
- They are provided through GitHub Actions Secrets.  
- This repo is for demonstration and learning purposes.
