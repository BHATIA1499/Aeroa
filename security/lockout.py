"""
Account Lockout & Progressive Delay
===================================
Per-ACCOUNT failed-login tracking, layered on top of the existing per-IP
rate limiter (security/rate_limiter.py). Two independent defences:

  - rate_limiter  -> caps requests per IP   (blunt, stops fast brute-force)
  - lockout       -> caps fails per ACCOUNT (locks the targeted account)

Policy
------
  - 5 consecutive failed logins  -> account locked for 15 minutes
  - Progressive delay: each failure adds an increasing server-side wait
    (0.5s, 1s, 2s, 4s ... capped) so online guessing is slowed long before
    the hard lock trips.
  - A successful login clears the counter.
  - The failure window decays: if the last failure was longer ago than the
    lock duration, the counter resets on its own.

Storage
-------
In-memory dict by default (single process). If REDIS_URL is set AND the redis
client is importable, state is kept in Redis so it survives restarts and is
shared across Railway replicas — mirroring rate_limiter.py's storage choice.
Any Redis error falls back to memory and never breaks login.

IMPORTANT (privacy / safety)
----------------------------
- The key is a hash of the lowercased email, never the raw email or password.
- Callers must surface the SAME generic message for "locked" and "wrong
  password" so the lockout state is never disclosed (see app.py auth_login).
"""

from __future__ import annotations

import hashlib
import os
import threading
import time

# ── Policy constants ──────────────────────────────────────────────────────────
MAX_FAILS = 5            # consecutive failures before lock
LOCK_SECONDS = 15 * 60   # 15-minute lockout
_BASE_DELAY = 0.5        # first progressive-delay step (seconds)
_MAX_DELAY = 5.0         # cap so we never tie up a worker too long
_KEY_PREFIX = "lockout:"


def _key(email: str) -> str:
    h = hashlib.sha256((email or "").strip().lower().encode("utf-8")).hexdigest()
    return _KEY_PREFIX + h


def _delay_for(fails: int) -> float:
    """Progressive back-off: grows with each failure, capped at _MAX_DELAY."""
    if fails <= 0:
        return 0.0
    return min(_BASE_DELAY * (2 ** (fails - 1)), _MAX_DELAY)


class _MemoryBackend:
    """Thread-safe in-process store. entry = {"fails": int, "until": float, "ts": float}."""

    def __init__(self) -> None:
        self._d: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            e = self._d.get(key)
            return dict(e) if e else None

    def set(self, key: str, entry: dict) -> None:
        with self._lock:
            self._d[key] = entry

    def delete(self, key: str) -> None:
        with self._lock:
            self._d.pop(key, None)


class _RedisBackend:
    """Redis-backed store using a small JSON blob per key with TTL."""

    def __init__(self, client) -> None:
        self._r = client

    def get(self, key: str) -> dict | None:
        import json
        raw = self._r.get(key)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def set(self, key: str, entry: dict) -> None:
        import json
        # Expire the record once the lock window can no longer be relevant.
        self._r.set(key, json.dumps(entry), ex=LOCK_SECONDS + 60)

    def delete(self, key: str) -> None:
        self._r.delete(key)


def _make_backend():
    url = os.environ.get("REDIS_URL", "")
    if url:
        try:
            import redis  # optional dependency
            client = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
            client.ping()
            return _RedisBackend(client)
        except Exception:
            # Redis unavailable / client not installed -> safe in-memory fallback.
            pass
    return _MemoryBackend()


class LockoutManager:
    def __init__(self) -> None:
        self._b = _make_backend()

    # ── Read-only check (call BEFORE attempting the password) ─────────────────
    def status(self, email: str) -> tuple[bool, float]:
        """
        Returns (is_locked, retry_after_seconds).
        Also auto-resets a stale counter whose window has fully decayed.
        """
        key = _key(email)
        e = self._b.get(key)
        if not e:
            return False, 0.0
        now = time.time()
        until = float(e.get("until", 0))
        if until > now:
            return True, round(until - now, 1)
        # Lock expired, or only partial fails with a decayed window.
        if now - float(e.get("ts", 0)) > LOCK_SECONDS:
            self._b.delete(key)
        return False, 0.0

    # ── Record outcomes ───────────────────────────────────────────────────────
    def record_failure(self, email: str) -> tuple[int, bool]:
        """
        Increment the consecutive-failure counter.
        Returns (fail_count, just_locked).
        """
        key = _key(email)
        now = time.time()
        e = self._b.get(key) or {"fails": 0, "until": 0.0, "ts": now}
        # Decay: if the previous failure is older than the lock window, start fresh.
        if now - float(e.get("ts", now)) > LOCK_SECONDS:
            e = {"fails": 0, "until": 0.0, "ts": now}
        e["fails"] = int(e.get("fails", 0)) + 1
        e["ts"] = now
        just_locked = False
        if e["fails"] >= MAX_FAILS:
            e["until"] = now + LOCK_SECONDS
            just_locked = True
        self._b.set(key, e)
        return e["fails"], just_locked

    def record_success(self, email: str) -> None:
        """Clear the counter on a successful login."""
        self._b.delete(_key(email))

    # ── Progressive delay helper ──────────────────────────────────────────────
    def delay_for_current(self, email: str) -> float:
        e = self._b.get(_key(email))
        return _delay_for(int(e.get("fails", 0))) if e else 0.0


# Module-level singleton, mirroring `audit` / `limiter` in app.py.
lockout = LockoutManager()
