import io
from pdfminer.high_level import extract_text as pdf_extract_text

from ai_client import make_openai_client


def _extract_pdf_text_cap(pdf_bytes: bytes, max_chars: int = 2000) -> str:
	"""
	Extracts text from a PDF and trims to max_chars.
	Keep it short to control token cost and latency.
	"""
	try:
		text = pdf_extract_text(io.BytesIO(pdf_bytes)) or ""
	except Exception:
		text = ""
	# collapse whitespace and cap length
	text = " ".join(text.split())
	return text[:max_chars]


def classify_invoice(subject: str, sender: str, filename: str, snippet: str = "",
	attachment_text: str | None = None, pdf_bytes: bytes | None = None) -> bool:
	"""
	Return True if the file is likely an invoice.
	- If attachment_text is provided (e.g., OCR/pdftotext), use it.
	- Else if pdf_bytes is provided, extract text from PDF.
	- Else, use subject/snippet/filename only.
	"""
	client = make_openai_client()

	if attachment_text is not None:
		body = attachment_text
		context = (
			f"Temat: {subject}\n"
			f"Nadawca: {sender}\n"
			f"Załącznik: {filename}\n"
			f"Tekst z załącznika (przycięty):\n{body}\n"
		)
	elif pdf_bytes:
		body = _extract_pdf_text_cap(pdf_bytes)
		context = (
			f"Temat: {subject}\n"
			f"Nadawca: {sender}\n"
			f"Załącznik: {filename}\n"
			f"Fragment tekstu z załącznika (przycięty):\n{body}\n"
		)
	else:
		context = (
			f"Temat: {subject}\n"
			f"Nadawca: {sender}\n"
			f"Część treści maila: {snippet}\n"
			f"Nazwa badanego pliku: {filename}\n"
		)

	prompt = (
		"Jesteś asystentem klasyfikującym załączniki e-maili po polsku.\n"
		"Uznaj za FAKTURĘ (odpowiedz YES), jeżeli z treści wynika którakolwiek z sytuacji:\n"
		"- „Faktura” / „Faktura VAT” / „Faktura uproszczona”.\n"
		"- „Paragon fiskalny” zawiera **NIP nabywcy** (to jest faktura uproszczona).\n"
		"- Występuje **NIP nabywcy** oraz elementy podatkowe "
		"(stawka VAT/PTU, kwota VAT, suma brutto/netto).\n"
		"- Są typowe pola faktury: numer dokumentu, dane sprzedawcy (NIP), "
		"data sprzedaży lub dostawy, pozycje towarów/usług, podsumowanie.\n"
		"Nie uznawaj za fakturę (odpowiedz NO), gdy to tylko:\n"
		"- paragon bez NIP nabywcy,\n"
		"- potwierdzenie płatności bez pozycji podatkowych,\n"
		"- oferta, regulamin, newsletter, kupon, ankieta itp.\n"
		"Ignoruj sekcje marketingowe, kody QR, kody kreskowe oraz napisy „NIEFISKALNY”"
		"w stopce, jeśli jednocześnie w treści jest „PARAGON FISKALNY” i **NIP nabywcy**.\n"
		f"{context}\n"
		"ODPOWIEDZ DOKŁADNIE: YES lub NO."
	)

	resp = client.chat.completions.create(
		model="gpt-4o-mini",
		messages=[{"role": "user", "content": prompt}],
		max_tokens=2,
		temperature=0,
	)
	ans = (resp.choices[0].message.content or "").strip().upper()
	return ans.startswith("Y")
