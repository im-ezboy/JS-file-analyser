from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional
from datetime import datetime


def _compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Drop None values to keep payloads lean."""
    return {k: v for k, v in data.items() if v is not None}


@dataclass
class Finding:
    type: str
    match: Optional[str]
    line: int
    severity: Optional[str] = None
    line_content: Optional[str] = None
    context: Optional[str] = None
    context_start_line: Optional[int] = None
    context_end_line: Optional[int] = None
    param_name: Optional[str] = None
    param_value: Optional[str] = None
    parameter: Optional[str] = None
    full_match: Optional[str] = None
    path: Optional[str] = None
    exploit_payload: Optional[str] = None
    verify_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _compact_dict(asdict(self))


@dataclass
class AnalysisResult:
    url: str
    api_keys: List[Finding] = field(default_factory=list)
    credentials: List[Finding] = field(default_factory=list)
    emails: List[Finding] = field(default_factory=list)
    interesting_comments: List[Finding] = field(default_factory=list)
    xss_vulnerabilities: List[Finding] = field(default_factory=list)
    xss_functions: List[Finding] = field(default_factory=list)
    api_endpoints: List[Finding] = field(default_factory=list)
    parameters: List[Finding] = field(default_factory=list)
    paths_directories: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    file_size: int = 0
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    waf_detected: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "url": self.url,
            "api_keys": [f.to_dict() for f in self.api_keys],
            "credentials": [f.to_dict() for f in self.credentials],
            "emails": [f.to_dict() for f in self.emails],
            "interesting_comments": [f.to_dict() for f in self.interesting_comments],
            "xss_vulnerabilities": [f.to_dict() for f in self.xss_vulnerabilities],
            "xss_functions": [f.to_dict() for f in self.xss_functions],
            "api_endpoints": [f.to_dict() for f in self.api_endpoints],
            "parameters": [f.to_dict() for f in self.parameters],
            "paths_directories": [f.to_dict() for f in self.paths_directories],
            "errors": list(self.errors),
            "file_size": self.file_size,
            "analysis_timestamp": self.analysis_timestamp,
        }
        if self.waf_detected:
            result["waf_detected"] = self.waf_detected
        return result


@dataclass
class SessionSummary:
    session_id: str
    total: int
    completed: int
    files: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total": self.total,
            "completed": self.completed,
            "files": self.files,
            "created_at": self.created_at,
            "urls": self.urls,
        }

