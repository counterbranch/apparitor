"""Durable, bounded local outbox for audit evidence."""

from __future__ import annotations

import asyncio
import logging
import os
import random
import sqlite3
import stat
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .audit import AuditEvidence


@dataclass(frozen=True)
class DeliveryEvent:
    """An opaque evidence payload and its stable remote idempotency key."""

    evidence_id: str
    payload: bytes


@dataclass(frozen=True)
class DeliveryResult:
    """Evidence IDs durably accepted by the receiver."""

    acknowledged: frozenset[str] = frozenset()


class AuditTransport(Protocol):
    def __call__(self, events: tuple[DeliveryEvent, ...]) -> Awaitable[DeliveryResult]: ...


@dataclass(frozen=True)
class CollectorStatus:
    pending: int
    pending_bytes: int
    delivered: int
    retries: int
    oldest_age_seconds: float | None
    failures: int
    refused: int
    conflicts: int


@dataclass(frozen=True)
class FlushResult:
    attempted: int
    delivered: int
    pending: int
    failures: int


class LocalAuditCollector:
    """SQLite-backed local outbox with explicit, caller-driven delivery."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        max_event_bytes: int = 65_536,
        max_pending_events: int = 10_000,
        max_pending_bytes: int = 64 * 1024 * 1024,
        lease_seconds: float = 30.0,
    ) -> None:
        if min(max_event_bytes, max_pending_events, max_pending_bytes) <= 0:
            raise ValueError("collector bounds must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._path = Path(path).expanduser().absolute()
        self._check_path()
        self._max_event_bytes = max_event_bytes
        self._max_pending_events = max_pending_events
        self._max_pending_bytes = max_pending_bytes
        self._lease_seconds = lease_seconds
        self._owner = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._closed = False
        self._connection = sqlite3.connect(
            self._path, timeout=10, isolation_level=None, check_same_thread=False
        )
        os.chmod(self._path, 0o600)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA busy_timeout=10000")
        self._connection.execute("PRAGMA wal_autocheckpoint=100")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS outbox (
                evidence_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                created_at REAL NOT NULL,
                retries INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_until REAL
            );
            CREATE TABLE IF NOT EXISTS counters (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS delivered_receipts (
                evidence_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                delivered_at REAL NOT NULL
            );
            """
        )

    def _check_path(self) -> None:
        parent = self._path.parent
        if not parent.exists() or parent.is_symlink() or not parent.is_dir():
            raise ValueError("collector parent must be an existing real directory")
        if parent.stat().st_uid != os.getuid():
            raise PermissionError("collector parent must be owned by the current user")
        try:
            info = self._path.lstat()
        except FileNotFoundError:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            return
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("collector path must be a regular file, not a symlink")
        if info.st_uid != os.getuid():
            raise PermissionError("collector database must be owned by the current user")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("collector is closed")

    def _increment(self, name: str, amount: int = 1) -> None:
        self._connection.execute(
            "INSERT INTO counters(name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
            (name, amount),
        )

    def record(self, record: AuditEvidence) -> None:
        payload = record.to_json().encode("utf-8")
        if len(payload) > self._max_event_bytes:
            with self._lock:
                self._ensure_open()
                self._increment("refused")
            raise ValueError("audit evidence exceeds max_event_bytes")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT payload FROM outbox WHERE evidence_id = ?", (record.evidence_id,)
                ).fetchone()
                if existing is None:
                    existing = self._connection.execute(
                        "SELECT payload FROM delivered_receipts WHERE evidence_id = ?",
                        (record.evidence_id,),
                    ).fetchone()
                if existing is not None:
                    if bytes(existing[0]) != payload:
                        self._increment("conflicts")
                        self._connection.execute("COMMIT")
                        raise ValueError("evidence_id already exists with different content")
                    self._connection.execute("COMMIT")
                    return
                count, size = self._connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM outbox"
                ).fetchone()
                if (
                    count >= self._max_pending_events
                    or size + len(payload) > self._max_pending_bytes
                ):
                    self._increment("refused")
                    self._connection.execute("COMMIT")
                    raise OverflowError("audit outbox capacity exceeded")
                self._connection.execute(
                    "INSERT INTO outbox(evidence_id, payload, created_at) VALUES (?, ?, ?)",
                    (record.evidence_id, payload, time.time()),
                )
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def status(self) -> CollectorStatus:
        with self._lock:
            self._ensure_open()
            pending, size, oldest = self._connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0), MIN(created_at) FROM outbox"
            ).fetchone()
            counters = dict(self._connection.execute("SELECT name, value FROM counters"))
        age = None if oldest is None else max(0.0, time.time() - float(oldest))
        return CollectorStatus(
            pending=int(pending),
            pending_bytes=int(size),
            delivered=counters.get("delivered", 0),
            retries=counters.get("retries", 0),
            oldest_age_seconds=age,
            failures=counters.get("failures", 0),
            refused=counters.get("refused", 0),
            conflicts=counters.get("conflicts", 0),
        )

    def _lease(self, batch_size: int) -> tuple[DeliveryEvent, ...]:
        now = time.time()
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                rows = self._connection.execute(
                    "SELECT evidence_id, payload FROM outbox "
                    "WHERE lease_until IS NULL OR lease_until < ? ORDER BY created_at LIMIT ?",
                    (now, batch_size),
                ).fetchall()
                ids = [row[0] for row in rows]
                if ids:
                    placeholders = ",".join("?" for _ in ids)
                    self._connection.execute(
                        f"UPDATE outbox SET lease_owner = ?, lease_until = ? "
                        f"WHERE evidence_id IN ({placeholders})",
                        (self._owner, now + self._lease_seconds, *ids),
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return tuple(DeliveryEvent(str(row[0]), bytes(row[1])) for row in rows)

    def _complete(self, events: tuple[DeliveryEvent, ...], acknowledged: frozenset[str]) -> int:
        offered = {event.evidence_id for event in events}
        if not acknowledged <= offered:
            raise ValueError("transport acknowledged an ID outside the delivered batch")
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                delivered = 0
                for evidence_id in acknowledged:
                    row = self._connection.execute(
                        "SELECT payload FROM outbox WHERE evidence_id = ? AND lease_owner = ?",
                        (evidence_id, self._owner),
                    ).fetchone()
                    if row is not None:
                        self._connection.execute(
                            "INSERT INTO delivered_receipts(evidence_id, payload, delivered_at) "
                            "VALUES (?, ?, ?)",
                            (evidence_id, row[0], time.time()),
                        )
                        self._connection.execute(
                            "DELETE FROM outbox WHERE evidence_id = ?", (evidence_id,)
                        )
                        delivered += 1
                receipt_count, receipt_bytes = self._connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM delivered_receipts"
                ).fetchone()
                while (
                    receipt_count > self._max_pending_events
                    or receipt_bytes > self._max_pending_bytes
                ):
                    self._connection.execute(
                        "DELETE FROM delivered_receipts WHERE evidence_id IN "
                        "(SELECT evidence_id FROM delivered_receipts "
                        "ORDER BY delivered_at LIMIT 1)"
                    )
                    receipt_count, receipt_bytes = self._connection.execute(
                        "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM delivered_receipts"
                    ).fetchone()
                remaining = offered - acknowledged
                if remaining:
                    placeholders = ",".join("?" for _ in remaining)
                    self._connection.execute(
                        f"UPDATE outbox SET retries = retries + 1, lease_owner = NULL, "
                        "lease_until = NULL WHERE lease_owner = ? "
                        f"AND evidence_id IN ({placeholders})",
                        (self._owner, *remaining),
                    )
                    self._increment("retries", len(remaining))
                if delivered:
                    self._increment("delivered", delivered)
                self._connection.execute("COMMIT")
                return delivered
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _release(self, events: tuple[DeliveryEvent, ...], *, failure: bool) -> None:
        ids = [event.evidence_id for event in events]
        with self._lock:
            if self._closed or not ids:
                return
            placeholders = ",".join("?" for _ in ids)
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    f"UPDATE outbox SET retries = retries + 1, lease_owner = NULL, "
                    f"lease_until = NULL WHERE lease_owner = ? AND evidence_id IN ({placeholders})",
                    (self._owner, *ids),
                )
                self._increment("retries", len(ids))
                if failure:
                    self._increment("failures")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    async def flush(
        self,
        transport: (
            AuditTransport | Callable[[tuple[DeliveryEvent, ...]], Awaitable[DeliveryResult]]
        ),
        *,
        batch_size: int = 100,
        retry_budget: int = 3,
        base_backoff: float = 0.1,
        max_backoff: float = 5.0,
    ) -> FlushResult:
        if batch_size <= 0 or retry_budget < 0 or base_backoff < 0 or max_backoff < 0:
            raise ValueError("invalid flush bounds")
        attempted = delivered = failures = 0
        for attempt in range(retry_budget + 1):
            events = self._lease(batch_size)
            if not events:
                break
            attempted += len(events)
            try:
                result = await transport(events)
                if not isinstance(result, DeliveryResult):
                    raise TypeError("transport must return DeliveryResult")
                delivered += self._complete(events, result.acknowledged)
            except asyncio.CancelledError:
                try:
                    self._release(events, failure=False)
                except (Exception, asyncio.CancelledError):
                    logging.getLogger("apparitor").warning(
                        "apparitor: collector lease cleanup failed during cancellation"
                    )
                raise
            except Exception:
                failures += 1
                self._release(events, failure=True)
            if attempt < retry_budget and self.status().pending:
                ceiling = min(max_backoff, base_backoff * (2**attempt))
                await asyncio.sleep(random.uniform(0, ceiling))
        return FlushResult(attempted, delivered, self.status().pending, failures)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> LocalAuditCollector:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
