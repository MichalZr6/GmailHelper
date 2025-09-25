import os
import re
import sys
import json
import base64
import httpx
import subprocess
from email.mime.text import MIMEText
from typing import List, Tuple
from dataclasses import dataclass
from openai import OpenAI
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from datetime import datetime
from zoneinfo import ZoneInfo


SCOPES = [
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/gmail.send",  # needed for your email reports
]


INVOICE_WORDS = ["invoice", "faktura", "proforma", "vat"]

SENDER_HINTS = [r"faktura"]

ATTACHMENT_HINTS = [r"invoice", r"faktura", r"proforma", r"rachunek"]


@dataclass
class LabelIds:
	incoming: str
	processed: str


def get_label_id(service, label_name: str) -> str:
	labels = service.users().labels().list(userId="me").execute().get("labels", [])
	for lb in labels:
		if lb.get("name", "").lower() == label_name.lower():
			return lb["id"]

	return ""


def resolve_labels(service) -> LabelIds:
	labels = service.users().labels().list(userId="me").execute().get("labels", [])
	# system INBOX (always "INBOX" regardless of UI language)
	inbox_id = next(label["id"] for label in labels if label["type"] == "system"
														and label["name"] == "INBOX")
	# user label: create if missing
	processed = next((label["id"] for label in labels if label["type"] == "user"
													and label["name"] == "instim/faktury"), None)
	if not processed:
		processed = get_label_id(service, "instim/faktury")
	return LabelIds(incoming=inbox_id, processed=processed)


def looks_like_invoice(subject: str, sender: str, filenames: List[str]) -> bool:
	s = subject.lower()
	if any(w in s for w in INVOICE_WORDS):
		return True
	snd = sender.lower()
	if any(re.search(h, snd) for h in SENDER_HINTS):
		return True
	for fn in filenames:
		lower = fn.lower()
		if lower.endswith(".pdf") and any(re.search(h, lower) for h in ATTACHMENT_HINTS):
			return True
	return False


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


def make_openai_client():
	"""
	Return an OpenAI client using our own httpx.Client so the SDK
	doesn't construct one (and won't pass 'proxies=...' internally).
	- Ignores system/env proxies by default (trust_env=False).
	- If HTTPS_PROXY/HTTP_PROXY is set, uses it explicitly.
	Works with httpx 0.27.x and 0.28+.
	"""
	proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")

	# pick correct kwarg for httpx 0.27 (proxies=) vs 0.28+ (proxy=)
	use_proxy_kw = False
	try:
		maj, min = (int(x) for x in (httpx.__version__ or "0.0").split(".")[:2])
		use_proxy_kw = (maj, min) >= (0, 28)
	except Exception:
		use_proxy_kw = False

	if proxy:
		if use_proxy_kw:
			http_client = httpx.Client(proxy=proxy, timeout=60.0, trust_env=False)
		else:
			http_client = httpx.Client(proxies=proxy, timeout=60.0, trust_env=False)
	else:
		http_client = httpx.Client(timeout=60.0, trust_env=False)

	return OpenAI(http_client=http_client)


def ai_invoice_classify(subject, snippet, sender, filenames):
	text = f"""
Subject: {subject}
From: {sender}
Snippet: {snippet}
Attachments: {", ".join(filenames)}

Is this email an invoice (YES/NO)?
"""
	client = make_openai_client()
	resp = client.chat.completions.create(
		model="gpt-4o-mini",
		messages=[{"role": "user", "content": text}],
		max_tokens=2,
		temperature=0
	)
	return resp.choices[0].message.content.strip().upper().startswith("Y")


def load_message(service, msg_id: str) -> dict:
	return service.users().messages().get(userId="me", id=msg_id, format="full").execute()


def get_header(msg, name) -> str:
	for h in msg.get("payload", {}).get("headers", []):
		if h["name"].lower() == name.lower():
			return h["value"]
	return ""


def iter_attachments(service, msg) -> List[Tuple[str, bytes]]:
	out = []
	payload = msg.get("payload", {})
	parts = payload.get("parts", []) or []
	stack = list(parts)
	while stack:
		p = stack.pop()
		if p.get("parts"):
			stack.extend(p["parts"])
			continue
		filename = p.get("filename", "")
		body = p.get("body", {})
		att_id = body.get("attachmentId")
		if filename and att_id:
			att = service.users().messages().attachments().get(
				userId="me", messageId=msg["id"], id=att_id
			).execute()
			data = att.get("data", "")
			out.append((filename, base64.urlsafe_b64decode(data)))
	return out


def sanitize_filename(name: str) -> str:
	name = name or "unnamed"
	root, ext = os.path.splitext(name)
	root = re.sub(r'[\\/:*?"<>|]+', "_", root).strip()[:140]
	ext = re.sub(r'[^.a-zA-Z0-9]', "", ext)[:10]  # keep safe ext
	return (root or "file") + (ext or ".dat")


def send_email_report(gmail_service, to_addr: str, subject: str, body: str) -> None:
	msg = MIMEText(body)
	msg['To'] = to_addr
	msg['From'] = 'me'
	msg['Subject'] = subject
	raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
	gmail_service.users().messages().send(userId='me', body={'raw': raw}).execute()


def upload_bytes_to_onedrive(file_bytes: bytes, out_name: str) -> None:
	"""Upload raw bytes to OneDrive via rclone rcat."""

	try:
		proc = subprocess.Popen(
			["rclone", "rcat", f"onedrive:Faktury/do_obrobienia/{out_name}"],
			stdin=subprocess.PIPE,
		)
		proc.communicate(file_bytes)
		if proc.returncode != 0:
			raise RuntimeError("rclone upload failed")
	except Exception as exc:
		print(f"OneDrive upload error: {exc}")


def mark_read(service, msg_id: str) -> None:
	service.users().messages().modify(
		userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
	).execute()


def label_modify(service, msg_id: str, to_add: List[str], to_remove: List[str]):
	body = {"addLabelIds": to_add, "removeLabelIds": to_remove}
	service.users().messages().modify(userId="me", id=msg_id, body=body).execute()


def get_my_email(service):
	return service.users().getProfile(userId="me").execute()["emailAddress"]


def main(svc) -> None:
	lbs = resolve_labels(svc)

	msgs = svc.users().messages().list(
		userId="me",
		q='in:inbox is:unread -label:"instim/faktury" has:attachment newer_than:7d',
	).execute().get("messages", [])

	if not msgs:
		to_addr = get_my_email(svc)
		if to_addr:
			send_email_report(svc, to_addr, "GmailHelper: seems like no invoices right now",
			"No unread emails matched at this run.")
		return

	report = []
	invoices = 0
	for m in msgs:
		msg = load_message(svc, m['id'])
		subj = get_header(msg, "Subject")
		from_header = get_header(msg, "From")
		snippet = msg.get("snippet", "")

		report.append(f"Processing potential invoice e-mail from {from_header} with subject: \n{subj}.")

		atts = iter_attachments(svc, msg)
		saved_any = False

		is_invoice = looks_like_invoice(subj, from_header, [fn for fn, _ in atts])

		if not is_invoice and any(
			fn.lower().endswith((".pdf", ".png", ".jpg", ".jpeg")) for fn, _ in atts
		):
			try:
				is_invoice = ai_invoice_classify(
					subj, snippet, from_header, [fn for fn, _ in atts]
				)
			except Exception as exc:
				report.append(f"AI classification error: {exc}")

		if not is_invoice:
			continue

		invoices += 1
		report.append("E-mail classified as invoice.")

		for fn, data in atts:
			try:
				if not fn.lower().endswith((".pdf", ".png", ".jpg", ".jpeg")):
					continue

				out_name = sanitize_filename(fn or "attachment")

				upload_bytes_to_onedrive(data, out_name)
				report.append(f"File {out_name} has been successfully uploaded to OneDrive")
				saved_any = True
			except Exception as exc:
				report.append(f"Attachment handling error: {exc}")
				continue

		report.append("\n\n")

		if saved_any:
			mark_read(svc, m['id'])
			to_add = [lbs.processed]
			to_remove = [lbs.incoming]
			label_modify(svc, m['id'], to_add, to_remove)

	if report:
		# --- email report ---
		to_addr = get_my_email(svc)
		if to_addr:
			body = "\n".join(report)
			subject = f"GmailHelper report - processed: {len(msgs)}, invoice(s): {invoices}"
			send_email_report(svc, to_addr, subject, body)


if __name__ == "__main__":
	now_pl = datetime.now(ZoneInfo("Europe/Warsaw"))
	if (7 <= now_pl.hour < 23):
		service = auth_gmail()
		try:
			main(service)
		except Exception as e:
			to_addr = get_my_email(service)
			try:
				send_email_report(service, to_addr or 'me', "GmailHelper: FATALity",
									f"{type(e).__name__}: {e}")
			except Exception:
				pass
			raise
	else:
		sys.exit(0)
