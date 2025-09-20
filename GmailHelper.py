import os, re, base64, json, pathlib, time
from dataclasses import dataclass
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


def resolve_labels(service) -> LabelIds:
	labels = service.users().labels().list(userId="me").execute().get("labels", [])
	# system INBOX (always "INBOX" regardless of UI language)
	inbox_id = next(label["id"] for label in labels if label["type"] == "system" 
														and label["name"] == "INBOX")
	# user label: create if missing
	processed = next((label["id"] for label in labels if label["type"] == "user" 
													and label["name"] == "instim/faktury"), None)
	if not processed:
		processed = get_or_create_label_id(service, "instim/faktury")
	return LabelIds(incoming=inbox_id, processed=processed)


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


def ai_invoice_classify(subject:str, snippet:str, from_):
	try:
		from openai import OpenAI
		client = OpenAI()
		text = f"Subject: {subject}\nFrom: {from_}\nSnippet: {snippet}\n\nIs this email an invoice? Reply with just YES or NO."
		resp = client.chat.completions.create(
			model="gpt-4o-mini",  # cheap/fast classifier
			messages=[{"role":"user","content":text}],
			max_tokens=2,
			temperature=0
		)
		ans = resp.choices[0].message.content.strip().upper()
		return ans.startswith("Y")
	except Exception:
		return None


def main():
	svc = auth_gmail()
	lbs = resolve_labels(svc)


	msgs = service.users().messages().list(userId="me", q="is:unread").execute().get("messages", [])

	for m in msgs:
		msg = load_message(svc, m.id)
		subj = header(msg,"Subject")
		frm  = header(msg,"From")
		snippet = msg.get("snippet","")

		# List attachment names
		atts = iter_attachments(svc, msg)
		filenames = [a[0] for a in atts]

		# 2) AI assist (optional) if rules unsure and there is any PDF
		if not is_invoice and any(fn.lower().endswith(".pdf") for fn in filenames):
			ai_guess = ai_invoice_classify(subj, snippet, frm)
			if ai_guess is True:
				is_invoice = True

		if not is_invoice:
			continue  # skip non-invoices

		# Download PDFs only
		saved_any = False
		for fn, data in atts:
			if not fn.lower().endswith(".pdf"):
				continue
			tag = safe_filename(subj or "no-subject")
			base = safe_filename(fn or "attachment.pdf")
			# optional: date prefix from internalDate
			ts = int(msg.get("internalDate","0")) // 1000
			ymd = time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "undated"
			out_name = f"{ymd} - {tag} - {base}"
			out_path = os.path.join(ONEDRIVE_INVOICES_DIR, out_name)
			with open(out_path,"wb") as f:
				f.write(data)
			saved_any = True

		if saved_any:
			# Move label: invoice -> invoices/processed, optionally remove INBOX
			to_add = [lbs.processed]
			to_remove = [lbs.incoming]
			if ONLY_FROM_INBOX:
				to_remove.append("INBOX")  # Gmail system label id is literally "INBOX"
			label_modify(svc, m.id, to_add, to_remove)

	print(lbs)


if __name__ == "__main__":
	main()
