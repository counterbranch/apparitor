"""Consistency checks for the curated compliance-jurisdiction catalog."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[2]
_CATALOG_PATH = _ROOT / "docs" / "compliance-jurisdictions.json"
_DOC_PATH = _ROOT / "docs" / "compliance-evidence.md"
_STATUSES = {"enacted_effective", "enacted_future", "proposed", "local_effective"}
_REQUIRED_OPERATIONAL_REGIMES = {
    "ca-ab-1405",
    "ca-sb-813",
    "ca-sb-942-ab-853",
    "ca-sb-243",
    "tx-sb-1188",
    "ut-hb-452",
}


def _catalog() -> dict:
    return json.loads(_CATALOG_PATH.read_text())


def test_catalog_has_unique_ids_official_sources_and_coherent_dates() -> None:
    catalog = _catalog()
    cutoff = date.fromisoformat(catalog["current_through"])
    entries = catalog["jurisdictions"]
    ids = [entry["id"] for entry in entries]
    assert len(ids) == len(set(ids))
    assert set(ids) >= _REQUIRED_OPERATIONAL_REGIMES
    assert catalog["schema_version"] == "apparitor.compliance-jurisdictions/v1"

    for entry in entries:
        assert entry["status"] in _STATUSES
        assert entry["source"].startswith("https://")
        assert entry["actors"] and entry["evidence_family"]
        if entry["status"] == "proposed":
            assert entry["enacted_date"] is None
            assert entry["effective_date"] is None
        else:
            enacted = date.fromisoformat(entry["enacted_date"])
            assert enacted <= cutoff
            if entry["effective_date"] is None:
                assert entry["effective_date_status"] == "conflicting_primary_notices"
                reported = entry["reported_effective_dates"]
                assert len(set(reported)) > 1
                assert all(date.fromisoformat(day) <= cutoff for day in reported)
                assert entry["date_verification_note"]
                continue
            effective = date.fromisoformat(entry["effective_date"])
            if entry["status"] in {"enacted_effective", "local_effective"}:
                assert effective <= cutoff
            else:
                assert effective > cutoff


def test_documented_table_mentions_every_catalog_entry() -> None:
    documentation = _DOC_PATH.read_text()
    for entry in _catalog()["jurisdictions"]:
        assert entry["id"] in documentation
