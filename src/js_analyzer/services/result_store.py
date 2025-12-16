from threading import Lock
from typing import Dict, List, Optional
from ..models import SessionSummary


class ResultStore:
    """In-memory result store (replaceable with Redis/DB later)."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionSummary] = {}
        self._lock = Lock()

    def create_session(self, session_id: str, total: int, urls: Optional[List[str]] = None) -> SessionSummary:
        with self._lock:
            summary = SessionSummary(session_id=session_id, total=total, completed=0, files=[], urls=urls or [])
            self._sessions[session_id] = summary
            return summary

    def add_result(self, session_id: str, file_result: Dict) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return
            session.files.append(file_result)
            session.completed += 1

    def get(self, session_id: str) -> Optional[SessionSummary]:
        with self._lock:
            return self._sessions.get(session_id)
    
    def get_all_sessions(self) -> List[SessionSummary]:
        """Get all sessions sorted by creation time (newest first)."""
        with self._lock:
            sessions = list(self._sessions.values())
            return sorted(sessions, key=lambda s: s.created_at, reverse=True)

