import os
import re
import base64
from typing import List, Tuple
from dataclasses import dataclass
from email.mime.text import MIMEText

from config import LABEL_PROCESSED


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
													and label["name"] == LABEL_PROCESSED), None)
	if not processed:
		processed = get_label_id(service, LABEL_PROCESSED)
	return LabelIds(incoming=inbox_id, processed=processed)


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


def mark_read(service, msg_id: str) -> None:
	service.users().messages().modify(
		userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
	).execute()


def label_modify(service, msg_id: str, to_add: List[str], to_remove: List[str]):
	body = {"addLabelIds": to_add, "removeLabelIds": to_remove}
	service.users().messages().modify(userId="me", id=msg_id, body=body).execute()


def get_my_email(service):
	return service.users().getProfile(userId="me").execute()["emailAddress"]
