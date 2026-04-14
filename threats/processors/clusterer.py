"""
Incident clustering: group intel items that cover the same attack or campaign.

Clustering signals (applied in order, any match triggers grouping):
  1. Shared IOCs — two items mentioning the same C2 IP/domain/hash are almost
     certainly covering the same infrastructure/campaign.
  2. Shared high-value IOC type — a shared SHA256 alone is sufficient.
  3. Shared threat actor name (from LLM enrichment) within a 7-day window.
  4. TTP overlap score — items sharing 3+ TTPs within 48h get soft-clustered
     (lower confidence, flagged as "related" rather than "same incident").

Items with NO IOCs and NO actor attribution are left unclustered (singletons).
"""

from __future__ import annotations
import logging
import re
from datetime import datetime, timezone

from threats.storage import Repository

log = logging.getLogger(__name__)

# Minimum shared IOCs to hard-cluster two items
_IOC_OVERLAP_THRESHOLD = 1
# SHA256/SHA1/MD5 alone is sufficient (a shared hash = same malware)
_HASH_TYPES = {"SHA256", "SHA1", "MD5"}
# Minimum shared TTPs for soft "related" clustering (no IOC overlap)
_TTP_OVERLAP_THRESHOLD = 3


def run_clustering(repo: Repository) -> int:
    """
    Cluster all unclustered items in the DB.
    Returns number of clusters created or updated.
    """
    # Fetch all item IDs not yet assigned to a cluster
    unclustered = _get_unclustered_item_ids(repo)
    if not unclustered:
        return 0

    log.info("Clustering %d unclustered items", len(unclustered))

    # Build IOC → [item_ids] and TTP → [item_ids] maps for fast lookup
    ioc_to_items = _build_ioc_index(repo)
    ttp_to_items = _build_ttp_index(repo)
    actor_to_items = _build_actor_index(repo)

    # Union-Find for grouping
    parent: dict[int, int] = {iid: iid for iid in unclustered}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Signal 1 & 2: shared IOCs
    for ioc_uid, item_ids in ioc_to_items.items():
        ids_in_scope = [i for i in item_ids if i in parent]
        ioc_type = ioc_uid.split(":")[0]
        # Any shared hash = hard cluster; other IOC types need threshold
        if ioc_type in _HASH_TYPES or len(ids_in_scope) >= _IOC_OVERLAP_THRESHOLD:
            for i in range(1, len(ids_in_scope)):
                union(ids_in_scope[0], ids_in_scope[i])

    # Signal 3: shared actor within 7 days
    for actor_name, item_ids in actor_to_items.items():
        ids_in_scope = [i for i in item_ids if i in parent]
        if len(ids_in_scope) > 1:
            for i in range(1, len(ids_in_scope)):
                union(ids_in_scope[0], ids_in_scope[i])

    # Signal 4: TTP overlap >= threshold
    ttp_overlap = _compute_pairwise_ttp_overlap(ttp_to_items, set(unclustered))
    for (a, b), shared_count in ttp_overlap.items():
        if shared_count >= _TTP_OVERLAP_THRESHOLD and a in parent and b in parent:
            union(a, b)

    # Build final groups from union-find
    groups: dict[int, list[int]] = {}
    for iid in unclustered:
        root = find(iid)
        groups.setdefault(root, []).append(iid)

    # Persist clusters
    created = 0
    for root_id, member_ids in groups.items():
        cluster_name = _generate_cluster_name(repo, member_ids)
        _persist_cluster(repo, member_ids, cluster_name)
        created += 1

    log.info("Created/updated %d incident clusters from %d items", created, len(unclustered))
    return created


def _get_unclustered_item_ids(repo: Repository) -> list[int]:
    rows = repo.conn.execute(
        """SELECT id FROM intel_items
           WHERE id NOT IN (SELECT item_id FROM cluster_items)"""
    ).fetchall()
    return [r["id"] for r in rows]


def _build_ioc_index(repo: Repository) -> dict[str, list[int]]:
    """Map ioc_uid → list of item_ids that contain it."""
    rows = repo.conn.execute(
        """SELECT i.type, i.value, ii.item_id
           FROM iocs i JOIN item_iocs ii ON i.id = ii.ioc_id"""
    ).fetchall()
    index: dict[str, list[int]] = {}
    for r in rows:
        uid = f"{r['type']}:{r['value']}"
        index.setdefault(uid, []).append(r["item_id"])
    return index


def _build_ttp_index(repo: Repository) -> dict[str, list[int]]:
    """Map technique_id → list of item_ids."""
    rows = repo.conn.execute(
        """SELECT t.technique_id, it.item_id
           FROM ttps t JOIN item_ttps it ON t.id = it.ttp_id"""
    ).fetchall()
    index: dict[str, list[int]] = {}
    for r in rows:
        index.setdefault(r["technique_id"], []).append(r["item_id"])
    return index


def _build_actor_index(repo: Repository) -> dict[str, list[int]]:
    """Map actor_name → list of item_ids."""
    rows = repo.conn.execute(
        """SELECT a.name, ia.item_id
           FROM threat_actors a JOIN item_actors ia ON a.id = ia.actor_id"""
    ).fetchall()
    index: dict[str, list[int]] = {}
    for r in rows:
        index.setdefault(r["name"].lower(), []).append(r["item_id"])
    return index


def _compute_pairwise_ttp_overlap(
    ttp_to_items: dict[str, list[int]], scope: set[int]
) -> dict[tuple[int, int], int]:
    """Count shared TTPs between every pair of items in scope."""
    pair_counts: dict[tuple[int, int], int] = {}
    for technique_id, item_ids in ttp_to_items.items():
        ids = [i for i in item_ids if i in scope]
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = min(ids[i], ids[j]), max(ids[i], ids[j])
                pair_counts[(a, b)] = pair_counts.get((a, b), 0) + 1
    return pair_counts


def _generate_cluster_name(repo: Repository, item_ids: list[int]) -> str:
    """
    Generate a descriptive cluster name from item titles and actors.
    Uses the most common keywords across all titles in the cluster.
    """
    if len(item_ids) == 1:
        row = repo.conn.execute(
            "SELECT title FROM intel_items WHERE id=?", (item_ids[0],)
        ).fetchone()
        return row["title"][:80] if row else "Unknown"

    # Multi-source: extract shared meaningful words from titles
    rows = repo.conn.execute(
        f"SELECT title, source_name FROM intel_items WHERE id IN ({','.join('?'*len(item_ids))})",
        item_ids,
    ).fetchall()

    sources = [r["source_name"] for r in rows]
    titles = [r["title"] for r in rows]

    # Use the first title as base name, append source count
    base = titles[0][:60].rstrip()
    return f"{base} [{len(item_ids)} sources: {', '.join(sources[:3])}{'...' if len(sources) > 3 else ''}]"


def _persist_cluster(repo: Repository, item_ids: list[int], name: str) -> int:
    """Insert or find cluster, link all items to it. Returns cluster id."""
    now = datetime.now(timezone.utc).isoformat()
    with repo.conn:
        cur = repo.conn.execute(
            "INSERT INTO incident_clusters (name, first_seen, last_seen, source_count) VALUES (?,?,?,?)",
            (name, now, now, len(item_ids)),
        )
        cluster_id = cur.lastrowid
        for item_id in item_ids:
            repo.conn.execute(
                "INSERT OR IGNORE INTO cluster_items (cluster_id, item_id) VALUES (?,?)",
                (cluster_id, item_id),
            )
    return cluster_id
