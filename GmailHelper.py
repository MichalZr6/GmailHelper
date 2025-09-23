import os, re, base64, json, pathlib, time
from typing import List, Optional, Tuple
from dataclasses import dataclass
import subprocess
from openai import OpenAI
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


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
	creds = None
	if os.path.exists("token.json"):
		creds = Credentials.from_authorized_user_file("token.json", SCOPES)
	if not creds or not creds.valid:
		if creds and creds.expired and creds.refresh_token:
			creds.refresh(Request())
		else:
			flow = InstalledAppFlow.from_client_secrets_file("gmail_credentials.json", SCOPES)
			creds = flow.run_local_server(port=0)
		with open("token.json", "w") as f:
			f.write(creds.to_json())
	return build("gmail", "v1", credentials=creds)


def ai_invoice_classify(subject, snippet, sender, filenames):
	text = f"""
Subject: {subject}
From: {sender}
Snippet: {snippet}
Attachments: {", ".join(filenames)}

Is this email an invoice (YES/NO)?
"""
	client = OpenAI()
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


def upload_bytes_to_onedrive(file_bytes: bytes) -> None:
	"""Upload raw bytes to OneDrive via rclone rcat."""

	try:
		proc = subprocess.Popen(
			["rclone", "rcat", "onedrive:Faktury/do_obrobienia"],
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


def main() -> None:
	
	print(">>> GmailHelper starting")

	svc = auth_gmail()
	lbs = resolve_labels(svc)

	msgs = svc.users().messages().list(
		userId="me",
		q='is:unread -label:"instim/faktury" has:attachment newer_than:7d',
	).execute().get("messages", [])

	if not msgs:
		print("No unread emails to process...")

	for m in msgs:
		msg = load_message(svc, m['id'])
		subj = get_header(msg, "Subject")
		from_header = get_header(msg, "From")
		snippet = msg.get("snippet", "")

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
				print(f"AI classification error: {exc}")

		if not is_invoice:
			continue

		print(f"E-mail from {from_header} with subject: {subj} classified as invoice.")

		uploaded = []
		for fn, data in atts:
			try:
				if not fn.lower().endswith((".pdf", ".png", ".jpg", ".jpeg")):
					continue

				out_name = sanitize_filename(fn or "attachment")

				upload_bytes_to_onedrive(data, out_name)
				uploaded.append(out_name)
				saved_any = True
			except Exception as exc:
				print(f"Attachment handling error: {exc}")
				continue

		if saved_any:
			mark_read(svc, m['id'])
			to_add = [lbs.processed]
			to_remove = [lbs.incoming]
			label_modify(svc, m['id'], to_add, to_remove)
			print(f"[OK] {subj!r} → {', '.join(uploaded)}")


if __name__ == "__main__":
	main()
