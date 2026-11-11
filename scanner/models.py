from dataclasses import dataclass, field
from typing import Any

@dataclass
class PageRecord:
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    cookies_present: bool
    html: str
    text: str
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)

@dataclass
class ToolRequest:
    name: str
    arguments: dict[str, Any]
    rationale: str = ""

@dataclass
class ToolResult:
    name: str
    allowed: bool
    executed: bool
    result: dict[str, Any]

@dataclass
class ScanRun:
    run_id: str
    pages: list[PageRecord]
    llm_input: dict[str, Any] | None = None
    llm_output: str | None = None
    tool_requests: list[ToolRequest] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
