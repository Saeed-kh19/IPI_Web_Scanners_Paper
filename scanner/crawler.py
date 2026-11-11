from urllib.parse import urljoin, urldefrag, urlparse
import requests
from bs4 import BeautifulSoup
from .models import PageRecord

class Crawler:
    def __init__(self, base_url: str, timeout: float = 10, max_pages: int = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()

    def _same_origin(self, url: str) -> bool:
        a, b = urlparse(url), urlparse(self.base_url)
        return a.scheme == b.scheme and a.netloc == b.netloc

    def fetch(self, url: str) -> PageRecord:
        r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text(" ", strip=True)

        links = []
        for tag in soup.find_all("a", href=True):
            u, _ = urldefrag(urljoin(r.url, tag["href"]))
            if self._same_origin(u):
                links.append(u)

        forms = []
        for form in soup.find_all("form"):
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                fields.append({
                    "tag": inp.name,
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                })
            forms.append({
                "action": urljoin(r.url, form.get("action") or r.url),
                "method": (form.get("method") or "GET").upper(),
                "fields": fields,
            })

        scripts = []
        for tag in soup.find_all("script", src=True):
            scripts.append(urljoin(r.url, tag["src"]))

        # Never persist raw cookie values in the research logs.
        headers = {k.lower(): v for k, v in r.headers.items()}
        return PageRecord(
            url=r.url,
            method="GET",
            status_code=r.status_code,
            headers=headers,
            cookies_present=bool(r.cookies) or ("set-cookie" in headers),
            html=r.text,
            text=text,
            links=sorted(set(links)),
            forms=forms,
            scripts=sorted(set(scripts)),
        )

    def crawl(self) -> list[PageRecord]:
        queue = [self.base_url + "/"]
        seen: set[str] = set()
        pages: list[PageRecord] = []
        while queue and len(pages) < self.max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                page = self.fetch(url)
            except requests.RequestException:
                continue
            pages.append(page)
            for link in page.links:
                if link not in seen and link not in queue:
                    queue.append(link)
        return pages
