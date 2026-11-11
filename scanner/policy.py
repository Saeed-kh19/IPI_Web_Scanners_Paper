from urllib.parse import urlparse

class PolicyValidator:
    def __init__(self, allowed_origin: str):
        p = urlparse(allowed_origin)
        self.allowed_scheme = p.scheme
        self.allowed_netloc = p.netloc

    def validate(self, tool_name: str, args: dict) -> tuple[bool, str]:
        if tool_name not in {"request", "inspect_response", "security_check"}:
            return False, "tool_not_allowlisted"
        url = args.get("url")
        if not isinstance(url, str):
            return False, "missing_url"
        p = urlparse(url)
        if (p.scheme, p.netloc) != (self.allowed_scheme, self.allowed_netloc):
            return False, "target_outside_allowed_origin"
        if tool_name == "request" and args.get("method", "GET").upper() not in {"GET", "POST"}:
            return False, "method_not_allowed"
        return True, "allowed"
