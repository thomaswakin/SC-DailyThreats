"""Shared requests.Session with retry logic, timeout, and User-Agent."""

import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_DEFAULT_UA = "ThreatIntelBot/1.0 (research; github.com/your-org/threats)"

_session: requests.Session | None = None


def get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = _build_session()
    return _session


def _build_session() -> requests.Session:
    timeout = int(os.getenv("HTTP_TIMEOUT", "30"))
    retries = int(os.getenv("HTTP_RETRIES", "3"))
    ua = os.getenv("HTTP_USER_AGENT", _DEFAULT_UA)
    proxy = os.getenv("HTTP_PROXY", "")

    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": ua})
    session.timeout = timeout  # type: ignore[attr-defined]

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    return session
