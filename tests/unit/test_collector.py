"""Tests for the durable local audit outbox."""

from __future__ import annotations

import asyncio
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from apparitor.audit import AuditMetadata, make_audit_evidence
from apparitor.collector import DeliveryResult, LocalAuditCollector

pytestmark = pytest.mark.unit


def _evidence(evidence_id: str, *, event_id: str = "evt"):
    record = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        verdict="block",
        evaluation_status="error",
        metadata=AuditMetadata(event_id=event_id, tenant_ref="tenant_opaque"),
    )
    return replace(record, evidence_id=evidence_id)


@pytest.mark.asyncio
async def test_reopen_preserves_pending_and_delivers(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    collector = LocalAuditCollector(path)
    record = _evidence("evd_one")
    collector.record(record)
    collector.close()

    reopened = LocalAuditCollector(path)
    seen = []

    async def transport(events):
        seen.extend(events)
        return DeliveryResult(frozenset(event.evidence_id for event in events))

    result = await reopened.flush(transport, base_backoff=0)
    assert result.delivered == 1
    assert seen[0].evidence_id == "evd_one"
    assert reopened.status().pending == 0
    assert reopened.status().delivered == 1

    reopened.record(record)
    assert reopened.status().pending == 0
    with pytest.raises(ValueError, match="different content"):
        reopened.record(_evidence("evd_one", event_id="changed"))
    reopened.close()


def test_idempotent_insert_and_conflict_are_observable(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3")
    record = _evidence("evd_same")
    collector.record(record)
    collector.record(record)
    with pytest.raises(ValueError, match="different content"):
        collector.record(replace(record, event_id="different"))
    status = collector.status()
    assert status.pending == 1
    assert status.conflicts == 1
    collector.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("bound", ["rows", "bytes"])
async def test_receipt_eviction_exposes_finite_deduplication_window(
    tmp_path: Path, bound: str
) -> None:
    path = tmp_path / "audit.sqlite3"
    first = _evidence("evd_first")
    second = _evidence("evd_other")
    limits = (
        {"max_pending_events": 1}
        if bound == "rows"
        else {"max_pending_bytes": max(len(first.to_json()), len(second.to_json())) + 16}
    )

    async def accept(events):
        return DeliveryResult(frozenset(event.evidence_id for event in events))

    with LocalAuditCollector(path, **limits) as collector:
        for record in (first, second):
            collector.record(record)
            assert (await collector.flush(accept)).delivered == 1
        assert collector.status().retained_receipts == 1
        assert collector.status().receipt_evictions == 1

    with LocalAuditCollector(path, **limits) as reopened:
        assert reopened.status().receipt_evictions == 1
        reopened.record(second)
        assert reopened.status().pending == 0
        with pytest.raises(ValueError, match="different content"):
            reopened.record(replace(second, event_id="changed"))
        reopened.record(replace(first, event_id="changed"))
        assert reopened.status().pending == 1
        assert reopened.status().conflicts == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_database_and_sidecars_remain_private_with_permissive_umask(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    record = _evidence("evd_private")
    original_umask = os.umask(0)
    try:
        for _ in range(2):
            with LocalAuditCollector(path) as collector:
                collector.record(record)
                files = list(tmp_path.glob("audit.sqlite3*"))
                assert {file.name for file in files} == {
                    "audit.sqlite3",
                    "audit.sqlite3-wal",
                    "audit.sqlite3-shm",
                }
                assert all(stat.S_IMODE(file.stat().st_mode) == 0o600 for file in files)
    finally:
        os.umask(original_umask)


def test_reopen_secures_existing_database_and_sidecars(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    with LocalAuditCollector(path) as first:
        first.record(_evidence("evd_existing"))
        files = list(tmp_path.glob("audit.sqlite3*"))
        assert len(files) == 3
        for file in files:
            file.chmod(0o666)
        with LocalAuditCollector(path) as second:
            assert second.status().pending == 1
            assert all(stat.S_IMODE(file.stat().st_mode) == 0o600 for file in files)


def test_rejects_writable_database_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    with pytest.raises(PermissionError, match="group- or world-writable"):
        LocalAuditCollector(parent / "audit.sqlite3")


def test_full_queue_refuses_without_discarding_existing_record(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3", max_pending_events=1)
    collector.record(_evidence("evd_one"))
    with pytest.raises(OverflowError, match="capacity"):
        collector.record(_evidence("evd_two"))
    status = collector.status()
    assert status.pending == 1
    assert status.refused == 1
    collector.close()


def test_oversize_record_is_refused_and_counted(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3", max_event_bytes=10)
    with pytest.raises(ValueError, match="max_event_bytes"):
        collector.record(_evidence("evd_large"))
    assert collector.status().refused == 1
    collector.close()


@pytest.mark.asyncio
async def test_retry_after_transport_failure(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3")
    collector.record(_evidence("evd_retry"))
    calls = 0

    async def transport(events):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic failure")
        return DeliveryResult(frozenset({events[0].evidence_id}))

    result = await collector.flush(transport, retry_budget=1, base_backoff=0)
    assert result.delivered == 1
    assert result.failures == 1
    assert collector.status().retries == 1
    assert collector.status().failures == 1
    collector.close()


@pytest.mark.asyncio
async def test_partial_acknowledgement_keeps_unacknowledged_event(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3")
    collector.record(_evidence("evd_one"))
    collector.record(_evidence("evd_two"))

    async def transport(events):
        return DeliveryResult(frozenset({events[0].evidence_id}))

    result = await collector.flush(transport, retry_budget=0)
    assert result.delivered == 1
    assert result.pending == 1
    assert collector.status().retries == 1
    collector.close()


@pytest.mark.asyncio
async def test_cancellation_releases_lease_and_preserves_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    collector = LocalAuditCollector(path)
    collector.record(_evidence("evd_cancel"))
    entered = asyncio.Event()

    async def blocked_transport(events):
        entered.set()
        await asyncio.Event().wait()
        return DeliveryResult()

    task = asyncio.create_task(collector.flush(blocked_transport, retry_budget=0))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    second = LocalAuditCollector(path)

    async def accepting_transport(events):
        return DeliveryResult(frozenset({events[0].evidence_id}))

    assert (await second.flush(accepting_transport, retry_budget=0)).delivered == 1
    collector.close()
    second.close()


@pytest.mark.asyncio
async def test_two_workers_do_not_deliver_same_lease_concurrently(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    first = LocalAuditCollector(path)
    second = LocalAuditCollector(path)
    first.record(_evidence("evd_once"))
    entered = asyncio.Event()
    release = asyncio.Event()
    seen: list[str] = []

    async def slow_transport(events):
        seen.extend(event.evidence_id for event in events)
        entered.set()
        await release.wait()
        return DeliveryResult(frozenset(seen))

    async def other_transport(events):
        seen.extend(event.evidence_id for event in events)
        return DeliveryResult(frozenset(event.evidence_id for event in events))

    active = asyncio.create_task(first.flush(slow_transport, retry_budget=0))
    await entered.wait()
    other = await second.flush(other_transport, retry_budget=0)
    release.set()
    await active
    assert other.attempted == 0
    assert seen == ["evd_once"]
    first.close()
    second.close()


def test_rejects_symlink_database(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.touch()
    link = tmp_path / "audit.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        LocalAuditCollector(link)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_rejects_symlink_sidecar(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / "audit.sqlite3"
    path.touch(mode=0o600)
    target = tmp_path / "target-wal"
    target.touch(mode=0o600)
    Path(f"{path}{suffix}").symlink_to(target)
    with pytest.raises(ValueError, match="sidecars"):
        LocalAuditCollector(path)


@pytest.mark.asyncio
async def test_diagnostics_contain_counts_only(tmp_path: Path) -> None:
    collector = LocalAuditCollector(tmp_path / "audit.sqlite3")
    collector.record(_evidence("secret-looking-id", event_id="do-not-report"))
    status = collector.status()
    assert "secret-looking-id" not in repr(status)
    assert "do-not-report" not in repr(status)
    assert status.oldest_age_seconds is not None
    collector.close()


@pytest.mark.asyncio
async def test_failed_lease_cleanup_preserves_cancellation_and_reopen_recovers(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    path = tmp_path / "audit.sqlite3"
    collector = LocalAuditCollector(path, lease_seconds=0.001)
    collector.record(_evidence("evd_pending"))
    original = asyncio.CancelledError("transport cancelled")

    async def cancel(events):
        raise original

    def fail_release(events, *, failure):
        raise RuntimeError("private-db-detail")

    monkeypatch.setattr(collector, "_release", fail_release)
    with pytest.raises(asyncio.CancelledError) as caught:
        await collector.flush(cancel)
    assert caught.value is original
    assert collector.status().pending == 1
    assert "private-db-detail" not in caplog.text
    collector.close()
    await asyncio.sleep(0.01)
    reopened = LocalAuditCollector(path)

    async def accept(events):
        return DeliveryResult(frozenset(event.evidence_id for event in events))

    assert (await reopened.flush(accept)).delivered == 1
    assert reopened.status().pending == 0
    reopened.close()
