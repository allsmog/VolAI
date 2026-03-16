"""SessionStore — CRUD operations for session persistence."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from volai.report.models import PluginOutput, TriageReport
from volai.storage.database import get_connection


class SessionStore:
    """Manages session persistence in SQLite."""

    def __init__(self, db_path: str | None = None) -> None:
        self._conn = get_connection(db_path)

    def close(self) -> None:
        self._conn.close()

    def create_session(
        self,
        dump_path: str,
        session_type: str,
        provider: str,
        model: str,
    ) -> dict:
        """Create a new session. Returns dict with session fields."""
        session_id = secrets.token_hex(4)
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO sessions (id, dump_path, session_type, provider, model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, dump_path, session_type, provider, model, now),
        )
        self._conn.commit()
        return {
            "id": session_id,
            "dump_path": dump_path,
            "session_type": session_type,
            "provider": provider,
            "model": model,
            "created_at": now,
            "status": "active",
        }

    def get_session(self, session_id: str) -> dict | None:
        """Get a session by ID."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_sessions(
        self,
        session_type: str | None = None,
        dump_path: str | None = None,
    ) -> list[dict]:
        """List sessions, optionally filtered."""
        query = "SELECT * FROM sessions"
        params: list = []
        conditions = []

        if session_type:
            conditions.append("session_type = ?")
            params.append(session_type)
        if dump_path:
            conditions.append("dump_path = ?")
            params.append(dump_path)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC"

        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all related data. Returns True if deleted."""
        # Delete related data first (foreign keys handle cascade, but be explicit)
        self._conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
        self._conn.execute("DELETE FROM plugin_outputs WHERE session_id = ?", (session_id,))
        self._conn.execute("DELETE FROM triage_reports WHERE session_id = ?", (session_id,))
        cursor = self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def save_message(self, session_id: str, role: str, content: str) -> None:
        """Save a chat message."""
        # Get next sequence number
        row = self._conn.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM messages WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        seq = row[0] + 1

        self._conn.execute(
            "INSERT INTO messages (session_id, role, content, sequence) VALUES (?, ?, ?, ?)",
            (session_id, role, content, seq),
        )
        self._conn.commit()

    def get_messages(self, session_id: str) -> list[dict]:
        """Get all messages for a session, ordered by sequence."""
        rows = self._conn.execute(
            "SELECT role, content, sequence FROM messages WHERE session_id = ? ORDER BY sequence",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def save_plugin_output(self, session_id: str, po: PluginOutput) -> None:
        """Save a plugin output."""
        self._conn.execute(
            "INSERT INTO plugin_outputs "
            "(session_id, plugin_name, columns_json, rows_json, row_count, error) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                session_id,
                po.plugin_name,
                json.dumps(po.columns),
                json.dumps(po.rows),
                po.row_count,
                po.error,
            ),
        )
        self._conn.commit()

    def get_plugin_outputs(self, session_id: str) -> list[PluginOutput]:
        """Get all plugin outputs for a session."""
        rows = self._conn.execute(
            "SELECT plugin_name, columns_json, rows_json, row_count, error "
            "FROM plugin_outputs WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        result = []
        for r in rows:
            result.append(PluginOutput(
                plugin_name=r["plugin_name"],
                columns=json.loads(r["columns_json"]) if r["columns_json"] else [],
                rows=json.loads(r["rows_json"]) if r["rows_json"] else [],
                row_count=r["row_count"],
                error=r["error"],
            ))
        return result

    def save_triage_report(self, session_id: str, report: TriageReport) -> None:
        """Save a triage report."""
        self._conn.execute(
            "INSERT INTO triage_reports (session_id, summary, risk_score, report_json) "
            "VALUES (?, ?, ?, ?)",
            (session_id, report.summary, report.risk_score, report.model_dump_json()),
        )
        self._conn.commit()

    def get_triage_report(self, session_id: str) -> TriageReport | None:
        """Get the triage report for a session."""
        row = self._conn.execute(
            "SELECT report_json FROM triage_reports WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row:
            return TriageReport.model_validate_json(row["report_json"])
        return None

    def export_session(self, session_id: str) -> dict | None:
        """Export a complete session as a dict."""
        session = self.get_session(session_id)
        if not session:
            return None

        messages = self.get_messages(session_id)
        plugin_outputs = self.get_plugin_outputs(session_id)
        report = self.get_triage_report(session_id)

        return {
            "session": session,
            "messages": messages,
            "plugin_outputs": [po.model_dump() for po in plugin_outputs],
            "triage_report": report.model_dump() if report else None,
        }

    def resolve_session_id(self, prefix: str) -> str | None:
        """Resolve a session ID prefix to a full ID. Returns None if ambiguous or not found."""
        rows = self._conn.execute(
            "SELECT id FROM sessions WHERE id LIKE ?", (prefix + "%",)
        ).fetchall()
        if len(rows) == 1:
            return rows[0]["id"]
        return None
