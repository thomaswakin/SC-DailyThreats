# Product Requirements Document
# Daily AI Threat Intelligence Briefing System

**Status:** Draft
**Last Updated:** 2026-04-13
**Owner:** [TBD]
**Engineering Contact:** [TBD]

---

## 1. Overview

This document defines the product requirements for a daily automated threat intelligence pipeline that aggregates content from curated security research sources, extracts structured indicators of compromise (IOCs) and adversary techniques (TTPs), generates analyst-grade daily briefings, and produces ready-to-deploy Sigma detection rules — all delivered on a configurable schedule.

*Business context and market rationale to be added by Product.*

---

## 2. User Personas

| Persona | Primary Need |
|---|---|
| **Security Analyst** | Concise daily briefing of what changed overnight; prioritized by severity |
| **Threat Hunter** | Curated IOC list with fidelity scores; MITRE ATT&CK mapping for hunting queries |
| **Detection Engineer** | Ready-to-deploy Sigma rules linked to specific campaigns and techniques |
| **SOC Manager** | High-level metrics: new threats, critical items, rule generation counts |
| **Incident Responder** | On-demand re-run for a specific date; structured JSON output for tooling integration |

---

## 3. Functional Requirements

### 3.1 Data Collection

| ID | Requirement |
|---|---|
| FR-COL-01 | The system MUST ingest from at minimum 20 curated threat intelligence sources covering nation-state APT, eCrime, malware research, incident response, cloud/container threats, network infrastructure, and vulnerability research. |
| FR-COL-02 | The system MUST support RSS-based collection and HTTP scraping as collection methods. |
| FR-COL-03 | The system MUST support AlienVault OTX as an optional supplemental feed (requires API key). |
| FR-COL-04 | The system MUST deduplicate articles across runs using a stable per-article hash derived from the source URL. |
| FR-COL-05 | The system MUST enforce a configurable lookback window (default: 72 hours) so that articles published between runs are not missed. |
| FR-COL-06 | The system MUST enforce per-domain request delays and timeouts to avoid overloading source servers. |
| FR-COL-07 | Individual feed failures MUST NOT halt collection from other feeds. |

### 3.2 IOC Extraction & Scoring

| ID | Requirement |
|---|---|
| FR-IOC-01 | The system MUST extract the following IOC types: IPv4 addresses, domains, URLs, MD5 hashes, SHA1 hashes, SHA256 hashes, email addresses, file paths/names, Windows Registry keys. |
| FR-IOC-02 | The system MUST normalize defanged indicators (e.g., `hxxp://`, `[.]`) before processing. |
| FR-IOC-03 | The system MUST exclude RFC 1918, loopback, and link-local IP addresses. |
| FR-IOC-04 | The system MUST maintain a curated false-positive exclusion list containing at minimum: vendor research domains, public DNS resolvers, and common legitimate cloud/SaaS services. |
| FR-IOC-05 | The system MUST classify each IOC with a fidelity level: HIGH, MEDIUM, LOW, or FP (false positive). |
| FR-IOC-06 | Fidelity MUST be computed from: source count (number of independent feeds reporting the IOC), confidence score, and hash type (cryptographic hashes receive elevated fidelity). |
| FR-IOC-07 | The system MUST flag context-dependent IOCs (e.g., Tor exit nodes, file-sharing platforms, remote access tools) separately from clean indicators, and MUST NOT use them as standalone detections. |
| FR-IOC-08 | The system MUST track first-seen and last-seen timestamps for all IOCs across runs. |
| FR-IOC-09 | The system MUST distinguish new IOCs (first seen this period) from re-observed IOCs (previously documented, seen again). |

### 3.3 TTP Extraction & Mapping

| ID | Requirement |
|---|---|
| FR-TTP-01 | The system MUST extract MITRE ATT&CK technique IDs (e.g., T1059.001) from article content. |
| FR-TTP-02 | The system MUST map extracted techniques to their parent tactic and human-readable name. |
| FR-TTP-03 | The system MUST track TTPs across runs, distinguishing new from re-observed techniques. |
| FR-TTP-04 | TTP extraction MUST function without LLM enrichment (via regex pattern matching as fallback). |

### 3.4 LLM Enrichment

| ID | Requirement |
|---|---|
| FR-LLM-01 | When an Anthropic API key is available, the system MUST enrich each collected article with: severity score (0.0–1.0), executive summary, MITRE ATT&CK technique IDs, targeted sectors, targeted regions, threat actor names and aliases, campaign names, malware family names, and concrete detection artifacts. |
| FR-LLM-02 | The system MUST perform a secondary LLM pass to validate IOC false-positive likelihood per article. |
| FR-LLM-03 | The system MUST perform a tertiary LLM pass to assess whether each IOC is attack-specific, ambiguous, or consistent with normal activity. |
| FR-LLM-04 | The system MUST generate a period-level executive summary synthesizing major threats across all collected items. |
| FR-LLM-05 | The system MUST enforce a configurable rate limit on LLM API calls (default: 40 requests/minute). |
| FR-LLM-06 | LLM input per article MUST be truncated to a configurable character limit (default: 10,000 characters) to control cost. |
| FR-LLM-07 | The pipeline MUST complete successfully when no API key is present, with all LLM-dependent fields omitted. |

### 3.5 Incident Clustering & Correlation

| ID | Requirement |
|---|---|
| FR-CLU-01 | The system MUST group related intelligence items into incident clusters when they share at least one of: identical IOC values (especially cryptographic hashes), the same named threat actor within a 7-day window, or 3 or more shared MITRE ATT&CK techniques within a 48-hour window. |
| FR-CLU-02 | Multi-source clusters (reported by 2+ independent feeds) MUST be ranked higher in briefing output than single-source items. |
| FR-CLU-03 | Each cluster MUST expose a consolidated union of all IOCs and TTPs from its member items. |
| FR-CLU-04 | The briefing MUST clearly separate multi-source clusters from singleton items. |

### 3.6 Sigma Rule Generation

| ID | Requirement |
|---|---|
| FR-SIG-01 | The system MUST auto-generate Sigma-format YAML detection rules for each intelligence item that contains concrete detection artifacts. |
| FR-SIG-02 | Rules MUST cover at minimum the following log source categories: process creation, file events, registry events, DNS queries, network connections, and firewall logs. |
| FR-SIG-03 | Each rule MUST include: a stable UUID, title, description, log source, detection conditions, MITRE ATT&CK tags, and severity level. |
| FR-SIG-04 | The system MUST generate composite IOC rules when two or more context-dependent IOCs co-occur within the same intelligence item. |
| FR-SIG-05 | Rules for recurring clusters MUST be versioned (version incremented, UUID preserved) rather than duplicated. |
| FR-SIG-06 | The system MUST perform a post-generation LLM review pass on each rule to: assign a false-positive risk level (low/medium/high), provide a brief rationale, and recommend a rule expiry window. |
| FR-SIG-07 | Severity levels assigned to rules for multi-source detections MUST be boosted one level above the base assessment. |
| FR-SIG-08 | Rules MUST be stripped of high-FP-risk IOCs when strong behavioral conditions are present. Rules consisting entirely of high-FP-risk IOCs with no behavioral conditions MUST be suppressed. |

### 3.7 Briefing Output

| ID | Requirement |
|---|---|
| FR-OUT-01 | The system MUST produce a daily briefing in Markdown format. |
| FR-OUT-02 | The system MUST produce a daily briefing in structured JSON format with the same content as the Markdown output. |
| FR-OUT-03 | Briefings MUST be named by date (`YYYY-MM-DD.md`, `YYYY-MM-DD.json`) and persisted to a configurable output directory. |
| FR-OUT-04 | The Markdown briefing MUST contain the following sections in order: executive summary, incident clusters (multi-source first), threat actor updates (new and returning), full intelligence item list sorted by severity, IOC inventory (new vs. re-observed, with fidelity labels), TTP inventory (new vs. re-observed), period metrics summary, and Sigma rule summary table. |
| FR-OUT-05 | The briefing MUST display severity at five levels: CRITICAL (≥80%), HIGH (60–79%), MEDIUM (40–59%), LOW (20–39%), INFORMATIONAL (<20%). |
| FR-OUT-06 | IOCs flagged as false positives MUST appear in the briefing with a visual suppression marker, not silently omitted. |
| FR-OUT-07 | The system MUST produce a downloadable IOC export (CSV + JSON in a ZIP archive) containing all non-FP IOCs with type, value, fidelity, confidence, source count, first-seen, last-seen, and expiry date. |

### 3.8 Scheduling & Delivery

| ID | Requirement |
|---|---|
| FR-SCH-01 | The system MUST support a background daemon mode that runs the pipeline automatically once per day at a configurable time (default: 06:00). |
| FR-SCH-02 | The system MUST support on-demand execution for today's date. |
| FR-SCH-03 | The system MUST support re-execution for any specific past date. |
| FR-SCH-04 | The system MUST deliver the briefing via email on schedule, to configurable recipient and CC lists. |
| FR-SCH-05 | Email delivery MUST attach the Sigma rules ZIP and IOC export ZIP when those artifacts are produced. |
| FR-SCH-06 | Email MUST be sent as multipart (plain text + HTML). |
| FR-SCH-07 | When no new threat data is collected, the system MUST send a notification email indicating no new items, rather than silently skipping. |
| FR-SCH-08 | Email delivery failures MUST NOT cause the pipeline run to be marked as failed. |

### 3.9 Persistence & Data Retention

| ID | Requirement |
|---|---|
| FR-DB-01 | The system MUST persist all raw and enriched intelligence items, IOCs, TTPs, threat actors, incident clusters, run logs, and Sigma rule version history to a local SQLite database. |
| FR-DB-02 | The database MUST enforce foreign key integrity. |
| FR-DB-03 | Raw intelligence items MUST be pruned after a configurable retention period (default: 90 days). |
| FR-DB-04 | IOC and TTP records MUST be retained indefinitely with first-seen/last-seen timestamps to enable longitudinal tracking. |
| FR-DB-05 | The run log MUST be retained indefinitely as an audit trail. |
| FR-DB-06 | The database schema MUST be self-migrating on startup (no manual migration steps). |

### 3.10 Observability

| ID | Requirement |
|---|---|
| FR-OBS-01 | The CLI MUST provide a status command displaying the last 10 pipeline runs with: date, start/end time, duration, items collected, items stored, IOCs found, Sigma rules generated, and run status. |
| FR-OBS-02 | The pipeline MUST log structured progress and errors throughout execution. |
| FR-OBS-03 | Each briefing MUST include a metrics summary section with: total clusters, multi-source vs. singleton split, new items count, critical + high item counts, new + returning actor counts, new + re-observed IOC counts by type, new + re-observed TTP counts, and Sigma rules generated. |

---

## 4. Non-Functional Requirements

### 4.1 Reliability

| ID | Requirement |
|---|---|
| NFR-REL-01 | The pipeline MUST complete a run even if any individual feed, LLM call, or email delivery fails. |
| NFR-REL-02 | Network requests MUST be retried with backoff on transient failures (minimum: 3 retries). |
| NFR-REL-03 | The system MUST produce output files (briefing MD/JSON) even when no IOCs are found. |

### 4.2 Cost Control

| ID | Requirement |
|---|---|
| NFR-COST-01 | Total LLM API calls per pipeline run MUST be bounded by a configurable maximum items limit (default: 200 items). |
| NFR-COST-02 | LLM input per article MUST be truncated before API submission. |
| NFR-COST-03 | The system MUST support a no-LLM mode that produces all non-LLM outputs at zero API cost. |

### 4.3 Performance

| ID | Requirement |
|---|---|
| NFR-PERF-01 | A standard daily run against all configured feeds MUST complete within a wall-clock time appropriate for a 06:00 scheduled job to be ready before a typical analyst's start of day. |
| NFR-PERF-02 | The system MUST enforce per-domain request delays to avoid impacting source server availability. |

### 4.4 Security

| ID | Requirement |
|---|---|
| NFR-SEC-01 | API keys and SMTP credentials MUST NOT be stored in configuration files in plaintext. |
| NFR-SEC-02 | SMTP credentials MUST be retrievable from the operating system credential store (e.g., macOS Keychain). |
| NFR-SEC-03 | Environment variables MUST be an accepted alternative to the credential store for all secrets. |

### 4.5 Portability & Configuration

| ID | Requirement |
|---|---|
| NFR-CFG-01 | All tunables (schedule time, retention, rate limits, output paths, LLM model, feed list) MUST be externalized to configuration files, not hardcoded. |
| NFR-CFG-02 | Any configuration file value MUST be overridable via an environment variable without modifying files. |
| NFR-CFG-03 | Feed sources MUST be defined in a declarative configuration file separate from application code. |

---

## 5. Inputs & Outputs Summary

### Inputs

| Input | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables LLM enrichment; pipeline functions without it |
| `OTX_API_KEY` | No | Enables AlienVault OTX feed |
| SMTP credentials | No | Enables email delivery |
| `config/feeds.yaml` | Yes | Declarative list of threat intelligence sources |
| `config/settings.yaml` | Yes | All runtime tunables |

### Outputs

| Output | Format | Location |
|---|---|---|
| Daily briefing | Markdown | `data/briefings/YYYY-MM-DD.md` |
| Daily briefing | JSON | `data/briefings/YYYY-MM-DD.json` |
| Sigma detection rules | YAML (Sigma format) | `data/sigma_rules/YYYY-MM-DD/` |
| IOC export bundle | CSV + JSON in ZIP | `data/briefings/ioc_exports/ioc_indicators_YYYY-MM-DD.zip` |
| Email delivery | HTML + plain text | Configured recipient list |
| Run status | CLI table | `threats-cli --status` |

---

## 6. Configuration Reference

The following settings MUST be user-configurable without code changes:

| Setting | Default | Description |
|---|---|---|
| `pipeline.lookback_hours` | 72 | Hours of history to collect per run |
| `pipeline.run_at` | `06:00` | Daily daemon schedule time (24h) |
| `pipeline.max_items_per_run` | 200 | Max articles to process (cost cap) |
| `pipeline.ioc_min_confidence` | 0.5 | Minimum confidence to include IOC in output |
| `llm.model` | `claude-opus-4-6` | Claude model to use for enrichment |
| `llm.rpm_limit` | 40 | LLM requests per minute |
| `llm.max_body_chars` | 10,000 | Article body truncation before LLM |
| `llm.disabled` | `false` | Disable LLM entirely |
| `http.timeout_seconds` | 30 | Per-request HTTP timeout |
| `http.retries` | 3 | Retry attempts on failure |
| `http.per_domain_delay` | 1.0 | Seconds between requests to same domain |
| `storage.db_path` | `data/db/threats.db` | SQLite database file path |
| `storage.retention_days` | 90 | Days to retain raw intelligence items |
| `output.briefings_dir` | `data/briefings/` | Briefing output directory |
| `output.sigma_dir` | `data/sigma_rules/` | Sigma rule output directory |
| `output.formats` | `md, json` | Briefing output formats |
| `sigma.status` | `experimental` | Default Sigma rule status metadata |
| `email.to` | — | Primary recipient list |
| `email.cc` | — | CC recipient list |
| `email.subject_prefix` | — | Email subject prefix |

---

## 7. CLI Interface Requirements

The system MUST expose a CLI with the following commands:

| Command | Description |
|---|---|
| `threats-cli --run-now` | Execute pipeline immediately for today |
| `threats-cli --run-date YYYY-MM-DD` | Execute pipeline for a specific past date |
| `threats-cli --daemon` | Start background scheduler |
| `threats-cli --status` | Show last 10 run summaries |
| `threats-cli --no-llm` | Run without LLM enrichment |
| `threats-cli --setup-email` | Interactive SMTP credential setup |
| `threats-cli --test-email` | Send test email to verify delivery |
| `threats-cli --settings <path>` | Override settings file path |
| `threats-cli --feeds <path>` | Override feeds file path |

---

## 8. Out of Scope

The following are explicitly not required for this product:

- Web UI or dashboard
- Multi-user access control or authentication
- Real-time / streaming pipeline (batch daily runs only)
- SIEM or EDR integrations (Sigma rules are the integration artifact; import is the user's responsibility)
- Automatic rule deployment to any platform
- Custom feed authoring UI
- Paid threat intelligence API integrations beyond OTX
- Cloud hosting or managed SaaS delivery

---

## 9. Open Questions

*To be resolved before engineering kickoff:*

1. Should email delivery support providers beyond SMTP (e.g., SendGrid, SES)?
2. Is macOS Keychain the only acceptable credential store, or should cross-platform alternatives (e.g., Linux secret service) be required?
3. What is the maximum acceptable end-to-end pipeline runtime for the daily run?
4. Should the JSON briefing output schema be versioned for downstream consumer stability?
5. Is the 90-day retention default acceptable for compliance purposes in all target environments?
