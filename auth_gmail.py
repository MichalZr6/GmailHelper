import os
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from config import SCOPES


def auth_gmail():
	"""
	Auth to Gmail using:
	- token.json  (authorized_user JSON with refresh_token)
	- gmail_credentials.json (OAuth client from GCP)
	Auto-refreshes access token and persists updates to token.json.
	"""
	creds = None

	# Load existing authorized_user token if present
	if os.path.exists("token.json") and os.path.getsize("token.json") > 0:
		with open("token.json", "r", encoding="utf-8") as f:
			info = json.load(f)
		creds = Credentials.from_authorized_user_info(info, scopes=SCOPES)

	# Refresh or run interactive OAuth if needed
	if not creds or not creds.valid:
		if creds and creds.expired and creds.refresh_token:
			creds.refresh(Request())
		else:
			flow = InstalledAppFlow.from_client_secrets_file("gmail_credentials.json", SCOPES)
			creds = flow.run_local_server(port=0)
		with open("token.json", "w", encoding="utf-8") as f:
			f.write(creds.to_json())

	return build("gmail", "v1", credentials=creds)
