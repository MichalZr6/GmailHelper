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
					pdf_bytes: bytes | None = None) -> bool:
	"""
	Return True if the file is likely an invoice.
	- Uses Polish instructions but forces a strict YES/NO output (English) for easy parsing.
	- If pdf_bytes is provided, uses extracted text; otherwise uses
		subject/snippet/filenames only.
	"""
	client = make_openai_client()

	if pdf_bytes:
		body = _extract_pdf_text_cap(pdf_bytes)
		context = (
			f"Temat: {subject}\n"
			f"Nadawca: {sender}\n"
			f"Załącznik: {filename}\n"
			f"Fragment tekstu z załącznika (ucięty):\n{body}\n"
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
		"Czy załącznik jest FAKTURĄ do księgowania ?\n"
		"Przeanalizuj treść i nazwę pliku, ale ignoruj stopki i linki marketingowe.\n\n"
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
