import subprocess


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
