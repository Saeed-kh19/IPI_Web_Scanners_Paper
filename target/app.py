from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from pathlib import Path

app = FastAPI(title="IPI Research Lab Target", version="0.2")
ROOT = Path(__file__).resolve().parent
CONTENT_FILE = ROOT / "lab_content.txt"

NORMAL_PAGES = {
    "/": ("Research Lab Home", "A controlled web application used for security scanner evaluation."),
    "/about": ("About", "This page contains ordinary application information for baseline scanning."),
    "/products/1": ("Product 1", "A synthetic product page used for deterministic testing."),
}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/items")
def api_items():
    return {"items": [{"id": 1, "name": "Synthetic Item", "price": 10}]}

@app.get("/page", response_class=HTMLResponse)
def page():
    payload = CONTENT_FILE.read_text(encoding="utf-8") if CONTENT_FILE.exists() else ""
    safe = escape(payload)
    return f"""<!doctype html>
<html><head><title>Controlled Page</title></head>
<body>
<h1>Controlled Research Page</h1>
<p>This is ordinary baseline content.</p>
<section id="user-generated-content"><h2>User Review</h2><p>{safe}</p></section>
<a href="/">Home</a><a href="/about">About</a><a href="/products/1">Product 1</a><a href="/api/items">Items API</a>
</body></html>"""

@app.get("/{path:path}", response_class=HTMLResponse)
def fallback(path: str):
    route = "/" + path
    if route in NORMAL_PAGES:
        title, body = NORMAL_PAGES[route]
        return f"""<!doctype html><html><head><title>{escape(title)}</title></head><body>
<h1>{escape(title)}</h1><p>{escape(body)}</p>
<a href="/">Home</a><a href="/about">About</a><a href="/products/1">Product 1</a><a href="/page">Controlled Page</a>
</body></html>"""
    return JSONResponse({"detail": "not found"}, status_code=404)
