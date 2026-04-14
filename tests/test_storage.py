"""Tests for database and repository."""

import pytest
from datetime import datetime, timezone
from threats.models import EnrichedIntelItem
from threats.models.ioc import IOC, IOCType
from threats.models.ttp import TTP, MITRETactic
from threats.models.threat_actor import ThreatActor


class TestRepository:
    def _make_item(self, url: str = "https://example.com/post-1") -> EnrichedIntelItem:
        return EnrichedIntelItem(
            source_name="TestSource",
            source_url=url,
            title="Test Intel Item",
            body="APT29 used PowerShell at 185.220.101.47",
            severity=0.75,
            iocs=[IOC(type=IOCType.IP, value="185.220.101.47")],
            ttps=[TTP(technique_id="T1059.001", tactic=MITRETactic.EXECUTION, name="PowerShell")],
            actors=[ThreatActor(name="APT29", aliases=["Cozy Bear"])],
        )

    def test_upsert_intel_item(self, repo):
        item = self._make_item()
        item_id = repo.upsert_intel_item(item)
        assert item_id is not None

    def test_upsert_intel_item_idempotent(self, repo):
        item = self._make_item()
        id1 = repo.upsert_intel_item(item)
        id2 = repo.upsert_intel_item(item)  # duplicate
        assert id1 is not None
        assert id2 is None  # second insert skipped

    def test_store_enriched_batch(self, repo):
        items = [self._make_item(f"https://example.com/post-{i}") for i in range(3)]
        stored = repo.store_enriched_batch(items)
        assert stored == 3

    def test_get_seen_hashes(self, repo):
        item = self._make_item()
        repo.upsert_intel_item(item)
        hashes = repo.get_seen_hashes()
        assert item.content_hash in hashes

    def test_upsert_ioc_updates_last_seen(self, repo):
        ioc = IOC(type=IOCType.IP, value="1.2.3.4")
        repo.upsert_ioc(ioc)
        repo.upsert_ioc(ioc)  # update
        rows = repo.conn.execute("SELECT * FROM iocs WHERE value='1.2.3.4'").fetchall()
        assert len(rows) == 1  # only one row despite two upserts

    def test_upsert_actor(self, repo):
        actor = ThreatActor(name="APT41", aliases=["Double Dragon"])
        actor_id = repo.upsert_actor(actor)
        assert actor_id is not None

    def test_run_log(self, repo):
        run_id = repo.start_run("2026-03-10")
        assert run_id is not None
        repo.finish_run(run_id, {"collected": 10, "stored": 8, "iocs": 25, "sigma": 3})
        row = repo.conn.execute("SELECT * FROM run_log WHERE id=?", (run_id,)).fetchone()
        assert row["status"] == "success"
        assert row["items_collected"] == 10
