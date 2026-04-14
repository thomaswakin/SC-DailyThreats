-- Daily Threat Intel - SQLite Schema
-- All timestamps stored as ISO8601 UTC strings

CREATE TABLE IF NOT EXISTS intel_items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash  TEXT    UNIQUE NOT NULL,  -- SHA-256 of source_url
    source_url    TEXT    NOT NULL,
    source_name   TEXT    NOT NULL,
    title         TEXT    NOT NULL DEFAULT '',
    body          TEXT    NOT NULL DEFAULT '',
    published_at  TEXT,
    fetched_at    TEXT    NOT NULL,
    summary       TEXT    DEFAULT '',       -- LLM-generated
    severity      REAL    DEFAULT 0.0,
    confidence    REAL    DEFAULT 0.5,
    llm_enriched  INTEGER DEFAULT 0,
    sigma_done    INTEGER DEFAULT 0,
    targeted_sectors TEXT DEFAULT '[]',     -- JSON array
    targeted_regions TEXT DEFAULT '[]',     -- JSON array
    detection_artifacts TEXT DEFAULT '[]'   -- JSON array of LLM-extracted detection conditions
);

CREATE INDEX IF NOT EXISTS idx_intel_items_fetched ON intel_items(fetched_at);
CREATE INDEX IF NOT EXISTS idx_intel_items_severity ON intel_items(severity);

-- ── IOCs ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS iocs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    type             TEXT    NOT NULL,    -- IP, DOMAIN, MD5, SHA256, SHA1, URL, EMAIL
    value            TEXT    NOT NULL,
    confidence       REAL    DEFAULT 0.5,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    specificity      TEXT    DEFAULT 'unknown',  -- attack_specific | ambiguous | normal | unknown
    specificity_note TEXT    DEFAULT '',          -- LLM rationale for specificity verdict
    tags             TEXT    DEFAULT '[]',        -- JSON array: CVEs, campaign names, malware families, actors
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);

-- ── TTPs ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ttps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id  TEXT    UNIQUE NOT NULL,   -- T1059.001
    tactic        TEXT    DEFAULT '',
    name          TEXT    DEFAULT '',
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL
);

-- ── Threat Actors ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_actors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    UNIQUE NOT NULL,
    aliases      TEXT    DEFAULT '[]',  -- JSON array
    description  TEXT    DEFAULT '',
    motivation   TEXT    DEFAULT '',
    origin       TEXT    DEFAULT '',
    confidence   REAL    DEFAULT 0.5,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actors_name ON threat_actors(name);

-- ── Junction Tables ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS item_iocs (
    item_id INTEGER NOT NULL REFERENCES intel_items(id) ON DELETE CASCADE,
    ioc_id  INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    PRIMARY KEY (item_id, ioc_id)
);

CREATE TABLE IF NOT EXISTS item_ttps (
    item_id INTEGER NOT NULL REFERENCES intel_items(id) ON DELETE CASCADE,
    ttp_id  INTEGER NOT NULL REFERENCES ttps(id) ON DELETE CASCADE,
    PRIMARY KEY (item_id, ttp_id)
);

CREATE TABLE IF NOT EXISTS item_actors (
    item_id  INTEGER NOT NULL REFERENCES intel_items(id) ON DELETE CASCADE,
    actor_id INTEGER NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
    PRIMARY KEY (item_id, actor_id)
);

-- ── Run Log ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS run_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date     TEXT    NOT NULL,   -- YYYY-MM-DD
    started_at   TEXT    NOT NULL,
    finished_at  TEXT,
    items_collected  INTEGER DEFAULT 0,
    items_stored     INTEGER DEFAULT 0,
    iocs_found       INTEGER DEFAULT 0,
    sigma_generated  INTEGER DEFAULT 0,
    status       TEXT    DEFAULT 'running'  -- running | success | error
);

-- ── Incident Clusters ─────────────────────────────────────────────────────────
-- Groups of intel items covering the same attack/campaign from multiple sources

CREATE TABLE IF NOT EXISTS incident_clusters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL DEFAULT '',   -- auto-generated slug or LLM name
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    source_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS cluster_items (
    cluster_id  INTEGER NOT NULL REFERENCES incident_clusters(id) ON DELETE CASCADE,
    item_id     INTEGER NOT NULL REFERENCES intel_items(id) ON DELETE CASCADE,
    PRIMARY KEY (cluster_id, item_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_items_item ON cluster_items(item_id);

-- ── Sigma Rule Registry (versioning) ─────────────────────────────────────────
-- Tracks generated behavioral Sigma rules across runs for versioning.
-- stable_key uniquely identifies a rule: technique+logsource+cluster/item identity.

CREATE TABLE IF NOT EXISTS sigma_rule_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    stable_key      TEXT    UNIQUE NOT NULL,
    rule_id         TEXT    NOT NULL,    -- stable UUID, never changes across versions
    title           TEXT    NOT NULL,
    version         INTEGER DEFAULT 1,
    first_generated TEXT    NOT NULL,
    last_updated    TEXT    NOT NULL,
    source_count    INTEGER DEFAULT 1,
    cluster_id      INTEGER,
    output_path     TEXT    DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rule_registry_key ON sigma_rule_registry(stable_key);
CREATE INDEX IF NOT EXISTS idx_rule_registry_cluster ON sigma_rule_registry(cluster_id);

-- ── Source Candidate Registry ─────────────────────────────────────────────
-- Tracks every URL ever evaluated for addition as a feed source.
-- Prevents re-evaluating the same candidate on every run.

CREATE TABLE IF NOT EXISTS source_candidates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT    UNIQUE NOT NULL,   -- feed URL or canonical site URL
    domain         TEXT    NOT NULL,
    name           TEXT    DEFAULT '',
    status         TEXT    DEFAULT 'pending', -- pending | approved | rejected
    discovered_via TEXT    DEFAULT '',        -- curated_list | citation
    citation_count INTEGER DEFAULT 0,         -- distinct source_names that cited this domain
    llm_verdict    TEXT    DEFAULT '',        -- LLM rationale (one sentence)
    reliability    TEXT    DEFAULT '',        -- authoritative | high | medium
    suggested_tags TEXT    DEFAULT '[]',      -- JSON array
    first_seen     TEXT    NOT NULL,
    evaluated_at   TEXT                       -- NULL until LLM evaluated
);

CREATE INDEX IF NOT EXISTS idx_source_candidates_status ON source_candidates(status);
CREATE INDEX IF NOT EXISTS idx_source_candidates_domain ON source_candidates(domain);
