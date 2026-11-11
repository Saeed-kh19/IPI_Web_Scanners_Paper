from urllib.parse import urljoin, urlparse
import requests

class ToolExecutor:
    """Allowlisted tool surface for the laboratory scanner."""
    def __init__(self, allowed_origin: str, timeout: float = 10):
        self.allowed_origin = allowed_origin.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _allowed_url(self, url: str) -> bool:
        a = urlparse(url)
        b = urlparse(self.allowed_origin)
        return a.scheme == b.scheme and a.netloc == b.netloc

    def inspect_response(self, url: str) -> dict:
        if not self._allowed_url(url):
            raise PermissionError("URL is outside the lab target origin")
        r = self.session.get(url, timeout=self.timeout)
        return {"status_code": r.status_code, "content_length": len(r.content), "content_type": r.headers.get("content-type")}

    def request(self, method: str, url: str, params: dict | None = None) -> dict:
        if method.upper() not in {"GET", "POST"}:
            raise ValueError("Only GET and POST are allowed in this lab")
        if not self._allowed_url(url):
            raise PermissionError("URL is outside the lab target origin")
        r = self.session.request(method.upper(), url, params=params if method.upper() == "GET" else None,
                                 data=params if method.upper() == "POST" else None, timeout=self.timeout)
        return {"status_code": r.status_code, "url": r.url, "content_length": len(r.content)}

    def security_check(self, url: str) -> dict:
        if not self._allowed_url(url):
            raise PermissionError("URL is outside the lab target origin")
        # Basic header check for the controlled lab target.
        r = self.session.get(url, timeout=self.timeout)
        return {
            "status_code": r.status_code,
            "checks": ["security_headers_present"],
            "security_headers_present": any(h.lower().startswith("x-") for h in r.headers),
        }
