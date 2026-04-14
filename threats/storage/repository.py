"""CRUD layer - all database reads and writes go through here."""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone, timedelta

from threats.models import EnrichedIntelItem
from threats.models.ioc import IOC
from threats.models.ttp import TTP
from threats.models.threat_actor import ThreatActor
from .database import Database

log = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def conn(self):
        return self._db.conn

    # ── Intel Items ───────────────────────────────────────────────────────────

    def get_seen_hashes(self) -> set[str]:
        rows = self.conn.execute("SELECT content_hash FROM intel_items").fetchall()
        return {r["content_hash"] for r in rows}

    def upsert_intel_item(self, item: EnrichedIntelItem) -> int | None:
        """Insert item; skip if hash already exists. Returns row id."""
        try:
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO intel_items
                  (content_hash, source_url, source_name, title, body,
                   published_at, fetched_at, summary, severity, confidence,
                   llm_enriched, targeted_sectors, targeted_regions)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    item.content_hash,
                    item.source_url,
                    item.source_name,
                    item.title,
                    item.body,
                    item.published_at.isoformat() if item.published_at else None,
                    item.fetched_at.isoformat(),
                    item.summary,
                    item.severity,
                    item.confidence,
                    int(item.llm_enriched),
                    json.dumps(item.targeted_sectors),
                    json.dumps(item.targeted_regions),
                ),
            )
            return cur.lastrowid if cur.rowcount > 0 else None
        except Exception as exc:
            log.error("upsert_intel_item error: %s", exc)
            return None

    def store_enriched_batch(self, items: list[EnrichedIntelItem]) -> int:
        """Store a batch of enriched items with all relations. Returns count stored."""
        stored = 0
        for item in items:
            try:
                with self.conn:
                    # Insert intel item
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO intel_items
                          (content_hash, source_url, source_name, title, body,
                           published_at, fetched_at, summary, severity, confidence,
                           llm_enriched, targeted_sectors, targeted_regions,
                           detection_artifacts)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            item.content_hash, item.source_url, item.source_name,
                            item.title, item.body,
                            item.published_at.isoformat() if item.published_at else None,
                            item.fetched_at.isoformat(), item.summary,
                            item.severity, item.confidence, int(item.llm_enriched),
                            json.dumps(item.targeted_sectors),
                            json.dumps(item.targeted_regions),
                            json.dumps(item.detection_artifacts),
                        ),
                    )
                    # Upsert IOCs/TTPs/actors then link via subquery (avoids lastrowid ambiguity)
                    # Skip likely false positives — don't persist them to the DB
                    for ioc in item.iocs:
                        if ioc.likely_fp:
                            continue
                        self.upsert_ioc(ioc)
                        self.conn.execute(
                            """INSERT OR IGNORE INTO item_iocs (item_id, ioc_id)
                               SELECT ii.id, c.id FROM intel_items ii, iocs c
                               WHERE ii.content_hash=? AND c.type=? AND c.value=?""",
                            (item.content_hash, ioc.type.value, ioc.value),
                        )
                    for ttp in item.ttps:
                        self.upsert_ttp(ttp)
                        self.conn.execute(
                            """INSERT OR IGNORE INTO item_ttps (item_id, ttp_id)
                               SELECT ii.id, t.id FROM intel_items ii, ttps t
                               WHERE ii.content_hash=? AND t.technique_id=?""",
                            (item.content_hash, ttp.technique_id),
                        )
                    for actor in item.actors:
                        self.upsert_actor(actor)
                        self.conn.execute(
                            """INSERT OR IGNORE INTO item_actors (item_id, actor_id)
                               SELECT ii.id, a.id FROM intel_items ii, threat_actors a
                               WHERE ii.content_hash=? AND a.name=?""",
                            (item.content_hash, actor.name),
                        )
                    stored += 1
            except Exception as exc:
                log.error("store_enriched_batch item error: %s", exc)
        return stored

    def get_clusters_since(self, since: datetime) -> list[dict]:
        """Return clusters with their member items, created/updated since `since`."""
        cluster_rows = self.conn.execute(
            "SELECT * FROM incident_clusters WHERE last_seen >= ? ORDER BY source_count DESC, last_seen DESC",
            (since.isoformat(),),
        ).fetchall()
        clusters = []
        for cr in cluster_rows:
            c = dict(cr)
            item_rows = self.conn.execute(
                """SELECT intel.* FROM intel_items intel
                   JOIN cluster_items ci ON intel.id = ci.item_id
                   WHERE ci.cluster_id = ?
                   ORDER BY intel.severity DESC""",
                (c["id"],),
            ).fetchall()
            c["items"] = [dict(r) for r in item_rows]
            # Aggregate IOCs across all items in cluster
            ioc_rows = self.conn.execute(
                """SELECT DISTINCT i.type, i.value, i.confidence, i.first_seen, i.last_seen
                   FROM iocs i
                   JOIN item_iocs ii ON i.id = ii.ioc_id
                   JOIN cluster_items ci ON ii.item_id = ci.item_id
                   WHERE ci.cluster_id = ?
                   ORDER BY i.confidence DESC""",
                (c["id"],),
            ).fetchall()
            c["iocs"] = [dict(r) for r in ioc_rows]
            # Aggregate TTPs
            ttp_rows = self.conn.execute(
                """SELECT DISTINCT t.technique_id, t.tactic, t.name
                   FROM ttps t
                   JOIN item_ttps it ON t.id = it.ttp_id
                   JOIN cluster_items ci ON it.item_id = ci.item_id
                   WHERE ci.cluster_id = ?""",
                (c["id"],),
            ).fetchall()
            c["ttps"] = [dict(r) for r in ttp_rows]
            clusters.append(c)
        return clusters

    def get_items_since(self, since: datetime) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM intel_items WHERE fetched_at >= ? ORDER BY severity DESC",
            (since.isoformat(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_unsigma_items(self) -> list[dict]:
        """Items that have never had Sigma rules generated (sigma_done=0)."""
        rows = self.conn.execute(
            "SELECT * FROM intel_items WHERE sigma_done=0 ORDER BY severity DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_sigma_done_since(self, since: datetime) -> int:
        """Mark all items fetched on or after `since` as sigma_done=1. Returns count updated."""
        cur = self.conn.execute(
            "UPDATE intel_items SET sigma_done=1 WHERE fetched_at >= ? AND sigma_done=0",
            (since.isoformat(),),
        )
        self.conn.commit()
        return cur.rowcount

    # ── IOCs ──────────────────────────────────────────────────────────────────

    def upsert_ioc(self, ioc: IOC) -> int | None:
        try:
            # Merge tags with any existing DB entry (union of old + new)
            existing = self.conn.execute(
                "SELECT tags FROM iocs WHERE type=? AND value=?",
                (ioc.type.value, ioc.value),
            ).fetchone()
            existing_tags: list[str] = json.loads(existing["tags"] or "[]") if existing else []
            merged_tags = json.dumps(sorted(set(existing_tags) | set(ioc.tags)))

            cur = self.conn.execute(
                """
                INSERT INTO iocs (type, value, confidence, first_seen, last_seen,
                                  specificity, specificity_note, tags)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(type, value) DO UPDATE SET
                  last_seen = excluded.last_seen,
                  confidence = MAX(confidence, excluded.confidence),
                  specificity = CASE WHEN excluded.specificity != 'unknown' THEN excluded.specificity ELSE specificity END,
                  specificity_note = CASE WHEN excluded.specificity_note != '' THEN excluded.specificity_note ELSE specificity_note END,
                  tags = ?
                """,
                (
                    ioc.type.value, ioc.value, ioc.confidence,
                    ioc.first_seen.isoformat(), ioc.last_seen.isoformat(),
                    ioc.specificity, ioc.specificity_note, merged_tags,
                    merged_tags,  # ON CONFLICT tags = ?
                ),
            )
            return cur.lastrowid
        except Exception as exc:
            log.error("upsert_ioc error: %s", exc)
            return None

    def get_active_iocs(self, since_days: int = 7) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
        rows = self.conn.execute(
            "SELECT * FROM iocs WHERE last_seen >= ? ORDER BY confidence DESC",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_iocs_since(self, since: datetime) -> list[dict]:
        """IOCs first seen on or after `since` (genuinely new this run/day)."""
        rows = self.conn.execute(
            """SELECT i.*,
                      (SELECT COUNT(DISTINCT it.source_name)
                       FROM item_iocs ii JOIN intel_items it ON ii.item_id=it.id
                       WHERE ii.ioc_id=i.id) AS source_count
               FROM iocs i
               WHERE i.first_seen >= ?
               ORDER BY i.confidence DESC""",
            (since.isoformat(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_reobserved_iocs_since(self, since: datetime) -> list[dict]:
        """IOCs seen before `since` but re-observed (last_seen updated) on/after `since`."""
        rows = self.conn.execute(
            """SELECT i.*,
                      (SELECT COUNT(DISTINCT it.source_name)
                       FROM item_iocs ii JOIN intel_items it ON ii.item_id=it.id
                       WHERE ii.ioc_id=i.id) AS source_count
               FROM iocs i
               WHERE i.first_seen < ? AND i.last_seen >= ?
               ORDER BY i.confidence DESC""",
            (since.isoformat(), since.isoformat()),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_ttps_since(self, since: datetime) -> list[dict]:
        """TTPs first documented on or after `since`."""
        rows = self.conn.execute(
            "SELECT * FROM ttps WHERE first_seen >= ? ORDER BY technique_id",
            (since.isoformat(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_reobserved_ttps_since(self, since: datetime) -> list[dict]:
        """TTPs seen before but re-observed on/after `since`."""
        rows = self.conn.execute(
            "SELECT * FROM ttps WHERE first_seen < ? AND last_seen >= ? ORDER BY technique_id",
            (since.isoformat(), since.isoformat()),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── TTPs ──────────────────────────────────────────────────────────────────

    def upsert_ttp(self, ttp: TTP) -> int | None:
        try:
            cur = self.conn.execute(
                """
                INSERT INTO ttps (technique_id, tactic, name, first_seen, last_seen)
                VALUES (?,?,?,?,?)
                ON CONFLICT(technique_id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (
                    ttp.technique_id,
                    ttp.tactic.value if ttp.tactic else "",
                    ttp.name,
                    _now(), _now(),
                ),
            )
            return cur.lastrowid
        except Exception as exc:
            log.error("upsert_ttp error: %s", exc)
            return None

    # ── Threat Actors ─────────────────────────────────────────────────────────

    def upsert_actor(self, actor: ThreatActor) -> int | None:
        try:
            cur = self.conn.execute(
                """
                INSERT INTO threat_actors
                  (name, aliases, description, motivation, confidence, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                  last_seen = excluded.last_seen,
                  aliases = CASE
                    WHEN length(excluded.aliases) > length(aliases) THEN excluded.aliases
                    ELSE aliases END
                """,
                (
                    actor.name,
                    json.dumps(actor.aliases),
                    actor.description,
                    actor.motivation,
                    actor.confidence,
                    actor.first_seen.isoformat(),
                    actor.last_seen.isoformat(),
                ),
            )
            return cur.lastrowid
        except Exception as exc:
            log.error("upsert_actor error: %s", exc)
            return None

    def get_new_actors_since(self, since: datetime) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM threat_actors WHERE first_seen >= ? ORDER BY confidence DESC",
            (since.isoformat(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_returning_actors_since(self, since: datetime) -> list[dict]:
        rows = self.conn.execute(
            """SELECT * FROM threat_actors
               WHERE first_seen < ? AND last_seen >= ?
               ORDER BY confidence DESC""",
            (since.isoformat(), since.isoformat()),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Run Log ───────────────────────────────────────────────────────────────

    def start_run(self, run_date: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO run_log (run_date, started_at, status) VALUES (?,?,?)",
            (run_date, _now(), "running"),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, stats: dict) -> None:
        self.conn.execute(
            """UPDATE run_log SET finished_at=?, items_collected=?, items_stored=?,
               iocs_found=?, sigma_generated=?, status=?
               WHERE id=?""",
            (
                _now(),
                stats.get("collected", 0),
                stats.get("stored", 0),
                stats.get("iocs", 0),
                stats.get("sigma", 0),
                "success",
                run_id,
            ),
        )
        self.conn.commit()

    def get_last_successful_run_at(self) -> "datetime | None":
        """Return finished_at of the most recent successful run, or None if no prior run."""
        row = self.conn.execute(
            "SELECT finished_at FROM run_log WHERE status='success' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row and row["finished_at"]:
            from datetime import timezone
            return datetime.fromisoformat(row["finished_at"]).replace(tzinfo=timezone.utc)
        return None

    # mark_sigma_done(item_ids) removed — use mark_sigma_done_since(since) instead

    # ── Sigma Rule Registry ───────────────────────────────────────────────────

    def get_rule_version(self, stable_key: str) -> dict | None:
        """Return existing registry entry for a stable_key, or None."""
        row = self.conn.execute(
            "SELECT * FROM sigma_rule_registry WHERE stable_key=?",
            (stable_key,),
        ).fetchone()
        return dict(row) if row else None

    def upsert_rule_version(
        self,
        stable_key: str,
        rule_id: str,
        title: str,
        source_count: int,
        cluster_id: int | None,
        output_path: str,
    ) -> int:
        """
        Insert or update a rule registry entry.
        Returns the current version number (1 for new, N+1 for update).
        """
        now = _now()
        existing = self.get_rule_version(stable_key)
        if existing is None:
            self.conn.execute(
                """INSERT INTO sigma_rule_registry
                   (stable_key, rule_id, title, version, first_generated, last_updated,
                    source_count, cluster_id, output_path)
                   VALUES (?,?,?,1,?,?,?,?,?)""",
                (stable_key, rule_id, title, now, now, source_count, cluster_id, output_path),
            )
            self.conn.commit()
            return 1
        else:
            new_version = existing["version"] + 1
            self.conn.execute(
                """UPDATE sigma_rule_registry
                   SET version=?, last_updated=?, source_count=?, output_path=?
                   WHERE stable_key=?""",
                (new_version, now, source_count, output_path, stable_key),
            )
            self.conn.commit()
            return new_version

    # ── Source Discovery ──────────────────────────────────────────────────────

    def get_known_candidate_urls(self) -> set[str]:
        """All URLs already recorded in source_candidates (any status)."""
        rows = self.conn.execute("SELECT url FROM source_candidates").fetchall()
        return {r["url"] for r in rows}

    def upsert_source_candidate(
        self,
        url: str,
        domain: str,
        name: str = "",
        status: str = "pending",
        discovered_via: str = "",
        citation_count: int = 0,
        llm_verdict: str = "",
        reliability: str = "",
        suggested_tags: list[str] | None = None,
        evaluated_at: str | None = None,
    ) -> None:
        now = _now()
        self.conn.execute(
            """
            INSERT INTO source_candidates
              (url, domain, name, status, discovered_via, citation_count,
               llm_verdict, reliability, suggested_tags, first_seen, evaluated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET
              status         = CASE WHEN excluded.status != 'pending' THEN excluded.status ELSE status END,
              citation_count = MAX(citation_count, excluded.citation_count),
              llm_verdict    = CASE WHEN excluded.llm_verdict != '' THEN excluded.llm_verdict ELSE llm_verdict END,
              reliability    = CASE WHEN excluded.reliability != '' THEN excluded.reliability ELSE reliability END,
              suggested_tags = CASE WHEN excluded.suggested_tags != '[]' THEN excluded.suggested_tags ELSE suggested_tags END,
              evaluated_at   = CASE WHEN excluded.evaluated_at IS NOT NULL THEN excluded.evaluated_at ELSE evaluated_at END
            """,
            (
                url, domain, name, status, discovered_via, citation_count,
                llm_verdict, reliability,
                json.dumps(suggested_tags or []),
                now, evaluated_at,
            ),
        )
        self.conn.commit()

    def get_cited_domains(self, min_sources: int = 3, lookback_days: int = 90) -> list[tuple[str, int]]:
        """
        Return (domain, distinct_source_count) for external domains referenced
        in article bodies more than min_sources distinct source_names.
        Used as the citation-based discovery signal.
        """
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        rows = self.conn.execute(
            "SELECT body, source_name FROM intel_items WHERE fetched_at >= ?",
            (cutoff,),
        ).fetchall()

        import re
        url_re = re.compile(r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:[/\s"\'<>)]|$)')
        domain_sources: dict[str, set[str]] = {}
        for row in rows:
            body = row["body"] or ""
            source = row["source_name"]
            for m in url_re.finditer(body):
                domain = m.group(1).lower().lstrip("www.")
                domain_sources.setdefault(domain, set()).add(source)

        return [
            (domain, len(sources))
            for domain, sources in domain_sources.items()
            if len(sources) >= min_sources
        ]

    # ── IOC source counts ─────────────────────────────────────────────────────

    def get_ioc_source_counts(self, ioc_type_values: list[tuple[str, str]]) -> dict[str, int]:
        """
        For a list of (type, value) tuples, return {type:value -> distinct_source_count}.
        Counts distinct source_names across all intel_items linked to each IOC.
        """
        if not ioc_type_values:
            return {}
        result: dict[str, int] = {}
        for ioc_type, ioc_val in ioc_type_values:
            row = self.conn.execute(
                """SELECT COUNT(DISTINCT it.source_name) as cnt
                   FROM iocs i
                   JOIN item_iocs ii ON i.id = ii.ioc_id
                   JOIN intel_items it ON ii.item_id = it.id
                   WHERE i.type=? AND i.value=?""",
                (ioc_type, ioc_val),
            ).fetchone()
            result[f"{ioc_type}:{ioc_val.lower()}"] = row["cnt"] if row and row["cnt"] else 1
        return result
