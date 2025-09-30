# ocr_utils.py  (stdlib-only OCR helpers; uses system binaries)
import os
import tempfile
import subprocess
import shlex


def _run(cmd: str, input_bytes: bytes | None = None,
		timeout: int = 60) -> tuple[int, bytes, bytes]:
	"""
	Run a shell command safely; return (rc, stdout, stderr).
	"""
	proc = subprocess.Popen(
		shlex.split(cmd),
		stdin=subprocess.PIPE if input_bytes is not None else None,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
	)
	stdout, stderr = proc.communicate(input=input_bytes, timeout=timeout)
	return proc.returncode, stdout, stderr


def pdftotext_first_pages(pdf_bytes: bytes, pages: int = 2) -> str:
	"""
	Fast path: extract text from the first N pages using poppler's pdftotext.
	If this returns enough text, you can skip OCR.
	"""
	with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as f:
		f.write(pdf_bytes)
		f.flush()
		# -l limits last page; -q quiet; '-' sends to stdout
		rc, out, err = _run(f"pdftotext -q -l {pages} {shlex.quote(f.name)} -")
		if rc == 0:
			return out.decode("utf-8", errors="ignore")
		return ""


def ocr_pdf_bytes(pdf_bytes: bytes, pages: int = 1, dpi: int = 300) -> str:
	"""
	Slow path: rasterize first N pages with pdftoppm, OCR each with tesseract, concat text.
	"""
	text_chunks: list[str] = []
	with tempfile.TemporaryDirectory() as td:
		with open(os.path.join(td, "in.pdf"), "wb") as f:
			f.write(pdf_bytes)
		# Render pages → PNG files like out-1.png, out-2.png
		rc, out, err = _run(f"pdftoppm -q -r {dpi} -png -f 1 -l "
						f"{pages} {shlex.quote(os.path.join(td, 'in.pdf'))} "
						f"{shlex.quote(os.path.join(td, 'out'))}")
		if rc != 0:
			return ""
		for i in range(1, pages + 1):
			png = os.path.join(td, f"out-{i}.png")
			if not os.path.exists(png):
				break
			# Tesseract to stdout; --psm 6 (block of text), --oem 1 (LSTM)
			rc2, out2, err2 = _run(f"tesseract {shlex.quote(png)} stdout -l pol --psm 6 --oem 1")
			if rc2 == 0 and out2:
				text_chunks.append(out2.decode("utf-8", errors="ignore"))
	return "\n".join(text_chunks).strip()


def ocr_image_bytes(image_bytes: bytes, ext: str = ".png", lang: str = "pol+eng") -> str:
	"""
	OCR a single image (PNG/JPG). Returns plain text.
	"""
	with tempfile.NamedTemporaryFile(suffix=ext, delete=True) as img:
		img.write(image_bytes)
		img.flush()
		rc, out, err = _run(f"tesseract {shlex.quote(img.name)} stdout -l {lang} --psm 6 --oem 1")
		if rc == 0:
			return out.decode("utf-8", errors="ignore").strip()
		return ""


def extract_text(filename: str, data: bytes, pdf_probe_chars: int = 200) -> str:
	"""
	Unified entry:
	- If PDF: try pdftotext first; if too short, OCR first pages.
	- If image: OCR directly.
	- Else: no OCR (return "") – caller can fall back to metadata-only.
	"""
	name = (filename or "").lower()
	if name.endswith(".pdf"):
		txt = pdftotext_first_pages(data, pages=2)
		if len(txt.strip()) >= pdf_probe_chars:
			return " ".join(txt.split())
		# scanned → OCR
		txt = ocr_pdf_bytes(data, pages=2, dpi=300)
		return " ".join(txt.split())
	if name.endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff")):
		txt = ocr_image_bytes(data, ext=os.path.splitext(name)[1] or ".png")
		return " ".join(txt.split())
	return ""
