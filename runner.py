import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from auth_gmail import auth_gmail
import gmail_ops as gmail
import invoice_classifier as inv_classifier

from storage import upload_bytes_to_onedrive
from config import LABEL_PROCESSED, TZ_NAME, RUN_HOURS


def main(svc) -> None:
	lbs = gmail.resolve_labels(svc)

	msgs = svc.users().messages().list(
		userId="me",
		q=f'in:inbox is:unread -label:"{LABEL_PROCESSED}" has:attachment newer_than:7d',
	).execute().get("messages", [])

	if not msgs:
		return

	report = []
	invoices = 0
	for m in msgs:
		msg = gmail.load_message(svc, m['id'])
		subj = gmail.get_header(msg, "Subject")
		from_header = gmail.get_header(msg, "From")
		snippet = msg.get("snippet", "")

		report.append("Processing potential invoice e-mail "
						f"from {from_header} with subject: \n{subj}.")

		attachments = gmail.iter_attachments(svc, msg)

		for att, data in attachments:
			if att.lower().endswith((".pdf", ".png", ".jpg", ".jpeg")):
				try:
					is_invoice = inv_classifier.classify_invoice(subj, snippet, from_header, att)
				except Exception as exc:
					report.append(f"AI classification error: {exc}")

			if not is_invoice:
				continue

			invoices += 1
			report.append(f"{att} is an invoice.")

			try:
				out_name = gmail.sanitize_filename(att or "attachment")

				upload_bytes_to_onedrive(data, out_name)
				report.append(f"File {out_name} has been successfully uploaded to OneDrive")
			except Exception as exc:
				report.append(f"Attachment handling error: {exc}")
				continue

			report.append("\n\n")

			gmail.mark_read(svc, m['id'])
			to_add = [lbs.processed]
			to_remove = [lbs.incoming]
			gmail.label_modify(svc, m['id'], to_add, to_remove)

	if invoices:
		# --- email report ---
		to_addr = gmail.get_my_email(svc)
		if to_addr:
			body = "\n".join(report)
			subject = f"GmailHelper report - processed: {len(msgs)}, invoice(s): {invoices}"
			gmail.send_email_report(svc, to_addr, subject, body)


def run():
	now_pl = datetime.now(ZoneInfo(TZ_NAME))
	start, end = RUN_HOURS
	if (start <= now_pl.hour < end):
		service = auth_gmail()
		try:
			main(service)
		except Exception as e:
			to_addr = gmail.get_my_email(service)
			try:
				gmail.send_email_report(service, to_addr or 'me', "GmailHelper: FATALity",
									f"{type(e).__name__}: {e}")
			except Exception:
				pass
			raise
	else:
		sys.exit(0)
