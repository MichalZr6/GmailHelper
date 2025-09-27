import os
import httpx
from openai import OpenAI


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
