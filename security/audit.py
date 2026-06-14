"""
Immutable Audit Logger
======================
GDPR Art. 30 / SOC 2 CC6.1 / ISO 27001 A.12.4 compliant audit trail.

Every write goes to the audit_logs table which has:
  - No UPDATE policy  → records cannot be modified
  - No DELETE policy  → records cannot be removed
  - INSERT-only RLS   → append-only from application layer

Logged events
-------------
USER_LOGIN        USER_LOGOUT       AUTH_FAILED
FILE_UPLOAD       FILE_DOWNLOAD     FILE_DELETED
REPORT_GENERATED  AI_QUERY          DATA_EXPORT
ROLE_CHANGE       USER_CREATED      USER_SUSPENDED
RATE_LIMITED      SECURITY_ALERT    PERMISSION_DENIED
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# ── Action constants ───────────────────────────────────────────────────────────
USER_LOGIN        = "USER_LOGIN"
USER_LOGOUT       = "USER_LOGOUT"
AUTH_FAILED       = "AUTH_FAILED"
FILE_UPLOAD       = "FILE_UPLOAD"
FILE_DOWNLOAD     = "FILE_DOWNLOAD"
FILE_DELETED      = "FILE_DELETED"
REPORT_GENERATED  = "REPORT_GENERATED"
AI_QUERY          = "AI_QUERY"
DATA_EXPORT       = "DATA_EXPORT"
ROLE_CHANGE       = "ROLE_CHANGE"
USER_CREATED      = "USER_CREATED"
USER_SUSPENDED    = "USER_SUSPENDED"
RATE_LIMITED      = "RATE_LIMITED"
SECURITY_ALERT    = "SECURITY_ALERT"
PERMISSION_DENIED = "PERMISSION_DENIED"
SETTINGS_CHANGED  = "SETTINGS_CHANGED"


def _get_ip(request) -> str:
    """Extract real client IP, honouring Railway / Cloudflare proxy headers."""
    for header in ("X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP"):
        val = request.headers.get(header, "")
        if val:
            return val.split(",")[0].strip()
    return request.remote_addr or "unknown"


class AuditLogger:
    """
    Thread-safe audit logger backed by Supabase.
    Errors are swallowed after logging — audit failures must never
    break normal application flow.
    """

    def __init__(self, supabase_client):
        self._db = supabase_client

    # ── Primary API ────────────────────────────────────────────────────────────

    def log(
        self,
        action:     str,
        *,
        request=    None,
        user_id:    Optional[str] = None,
        company_id: Optional[str] = None,
        resource:   Optional[str] = None,
        status:     str           = "SUCCESS",
        metadata:   Optional[dict] = None,
    ) -> None:
        """
        Append one immutable audit record.

        Parameters
        ----------
        action      : One of the constants above (e.g. AuditLogger.FILE_UPLOAD)
        request     : Flask request object (used to extract IP + User-Agent)
        user_id     : UUID of the acting user
        company_id  : UUID of the user's company
        resource    : What was acted upon (e.g. "upload:abc-123", "report:weekly")
        status      : "SUCCESS" | "FAILURE" | "BLOCKED"
        metadata    : Extra context — never store raw PII or secrets here
        """
        try:
            ip         = _get_ip(request) if request else "system"
            user_agent = ""
            if request:
                user_agent = (request.headers.get("User-Agent") or "")[:500]

            entry = {
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "user_id":    str(user_id)    if user_id    else None,
                "company_id": str(company_id) if company_id else None,
                "action":     action,
                "resource":   str(resource)[:500] if resource else None,
                "ip_address": ip,
                "user_agent": user_agent,
                "status":     status,
                "metadata":   json.dumps(metadata or {}),
            }
            self._db.table("audit_logs").insert(entry).execute()

        except Exception as exc:
            # Never crash the request over audit failure
            log.error(f"[AUDIT] Failed to write log entry: {exc}", exc_info=True)

    # ── Query API (Security Centre) ────────────────────────────────────────────

    def recent(self, company_id: str, limit: int = 100) -> list[dict]:
        """Return most recent audit entries for a company."""
        try:
            res = (
                self._db.table("audit_logs")
                .select("*")
                .eq("company_id", str(company_id))
                .order("timestamp", desc=True)
                .limit(limit)
                .execute()
            )
            return res.data or []
        except Exception as exc:
            log.error(f"[AUDIT] Failed to query audit logs: {exc}")
            return []

    def security_events(self, company_id: str, limit: int = 50) -> list[dict]:
        """Return only security-relevant events (failures, alerts, blocked)."""
        try:
            res = (
                self._db.table("audit_logs")
                .select("*")
                .eq("company_id", str(company_id))
                .in_("status", ["FAILURE", "BLOCKED"])
                .order("timestamp", desc=True)
                .limit(limit)
                .execute()
            )
            return res.data or []
        except Exception as exc:
            log.error(f"[AUDIT] Failed to query security events: {exc}")
            return []

    def stats(self, company_id: str) -> dict:
        """Aggregate stats for Security Centre dashboard."""
        try:
            res = (
                self._db.table("audit_logs")
                .select("action, status")
                .eq("company_id", str(company_id))
                .execute()
            )
            rows   = res.data or []
            counts = {}
            blocked = 0
            for r in rows:
                counts[r["action"]] = counts.get(r["action"], 0) + 1
                if r["status"] in ("FAILURE", "BLOCKED"):
                    blocked += 1
            return {
                "total_events":   len(rows),
                "blocked_events": blocked,
                "event_counts":   counts,
            }
        except Exception as exc:
            log.error(f"[AUDIT] Failed to compute stats: {exc}")
            return {"total_events": 0, "blocked_events": 0, "event_counts": {}}
