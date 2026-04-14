# Threat Intelligence Agent — Product Requirements

**Document status:** Draft for Engineering Handoff
**Purpose:** Define outcomes and requirements for an internal AI agent that produces customer-ready threat intelligence. This document describes *what* the system must do and the quality bar it must meet. Implementation approach, architecture, and technology choices are left to engineering.

---

## 1. Overview

The system is an automated AI agent that runs on a recurring schedule and produces three deliverables:

1. **A daily IOC feed** — high-fidelity indicators of compromise with supporting context
2. **Detection rules** — Sigma-format behavioral detection rules ready for SIEM/EDR deployment
3. **A validation gate** — automated testing that every IOC and rule must pass before reaching customers

The agent operates without human review of individual items. Quality must be enforced by the system itself. Anything that cannot be validated to the required confidence threshold must be held back, not shipped with a caveat.

---

## 2. Inputs

### 2.1 Intelligence Sources

The agent must ingest from a minimum of:

- **Vendor threat research blogs** — major security vendors (e.g., Mandiant, CrowdStrike, Unit42, Talos, ESET, SentinelOne, Elastic, Recorded Future, Secureworks, Proofpoint, CheckPoint, Trend Micro)
- **Government and national advisories** — CISA, NCSC, FBI flash alerts, and equivalent
- **Community and open-source feeds** — OTX, ThreatFox, URLhaus, CISA KEV
- **Incident response reports** — DFIR and incident writeups from recognized research groups

The source list must be configurable without code changes. The system must be able to add, remove, or adjust source weighting via configuration.

### 2.2 Source Reliability

Sources must be weighted by reliability. A single report from a tier-1 vendor (Mandiant, CrowdStrike, Unit42) carries more inherent weight than a single community submission. Reliability tiers must be configurable.

---

## 3. IOC Feed Requirements

### 3.1 What Must Be Extracted

The system must extract the following indicator types from source content:

| Type | Examples |
|------|---------|
| IPv4 addresses | C2 servers, staging infrastructure |
| Domains and FQDNs | Attacker-registered, DGA-generated, typosquatted |
| URLs | Payload delivery, C2 callback, phishing kit |
| File hashes | MD5, SHA-1, SHA-256 of malicious samples |
| Email addresses | Spear-phishing senders, registrant contacts |
| Filenames | Malware droppers, renamed system binaries |
| Registry keys | Persistence locations |

Defanged indicators (e.g., `hxxps://`, `evil[.]com`) must be normalized to standard form before processing.

### 3.2 Fidelity Scoring

Every IOC in the feed must carry a fidelity label: **high**, **medium**, or **low**. The fidelity computation must incorporate:

- **Source count** — how many independent sources reported this indicator. An IOC appearing in four separate vendor reports is materially higher fidelity than one appearing in one.
- **Source reliability** — the tier of each reporting source
- **IOC type** — file hashes are inherently attack-specific; IP addresses of shared hosting are not. The scoring model must account for this.
- **Attack specificity** — whether the indicator is unique to attacker tooling/infrastructure or could plausibly appear in normal activity. A randomly generated domain name or a lookalike process filename is attack-specific even if seen only once. A base cloud storage domain is not. The system must reason about this distinction, not just count sources.
- **False positive signals** — indicators that are known-good values, impersonation targets, or vendor reference links must be suppressed or clearly flagged

Fidelity thresholds:

| Label | Minimum requirement |
|-------|---------------------|
| **high** | 3+ independent sources, OR 2+ sources with high source reliability AND confirmed attack-specific |
| **medium** | 2+ sources, OR single source with confirmed attack-specific classification |
| **low** | Single source, attack-specificity unconfirmed or ambiguous |

IOCs classified as **likely false positive** must never appear in the customer feed. They may be logged internally for audit.

### 3.3 Required Metadata Per IOC

Each IOC in the feed must include:

- Indicator type and value
- Fidelity label (high / medium / low)
- Source count (number of independent sources)
- First seen date and last seen date
- **Tags** — one or more of the following context labels where known:
  - Vulnerability reference (CVE ID)
  - Campaign or operation name (e.g., "Operation ShadowHammer", "Volt Typhoon")
  - Malware family or tool name (e.g., "LockBit 3.0", "Cobalt Strike")
  - Threat actor attribution (e.g., "APT29", "Lazarus Group")
- Specificity note — a brief human-readable rationale for the fidelity and specificity classification (e.g., "DGA-pattern domain confirmed as C2 in two independent reports")
- Context-dependency flag — if the IOC is only meaningful in combination with other indicators (e.g., a widely-used cloud service used for staging), this must be explicitly flagged

### 3.4 IOC Feed Delivery

- **Format:** The feed must be available in at least two machine-readable formats. One must be structured (e.g., JSON, STIX). One must be human-readable (e.g., Markdown report).
- **Cadence:** At minimum daily. The system must track the last successful run and process only new content since that point, with a configurable overlap buffer to avoid gaps at the boundary.
- **Deduplication:** An IOC must not appear multiple times within a single feed delivery. Across runs, the same IOC reappearing must be treated as re-observed and labeled accordingly — not as a new indicator.

---

## 4. Sigma Rule Requirements

### 4.1 Rule Quality Bar

Sigma rules produced by the system must meet the quality standard expected for production SIEM/EDR deployment. This means:

- **Behavioral, not indicator-based** — rules must detect attacker *behavior* (process execution patterns, registry modifications, network callback patterns, lateral movement techniques) rather than simply matching on a known-bad IP or hash. IP and hash matching belongs in the IOC feed, not in Sigma rules.
- **Grounded in observed artifacts** — every detection condition in a rule must be traceable to a concrete artifact described in the source report (a specific process name, command-line substring, registry key path, network destination port, or DNS query pattern). Rules must not be generated from generic descriptions or inferred beyond what the source states.
- **MITRE ATT&CK aligned** — every rule must map to one or more ATT&CK technique IDs. The technique ID must appear in the rule metadata.
- **Log source specificity** — rules must specify the log source (platform, category) required for the detection to function. A rule requiring Windows process creation logs must say so explicitly.

### 4.2 Required Rule Metadata

Each Sigma rule must include:

- Unique stable rule ID (persists across rule versions)
- Version number (incremented when the rule is updated)
- Title and description
- MITRE ATT&CK technique reference(s)
- Log source (product, category)
- Date created and date last modified
- Linked campaign name, malware family, or threat actor where applicable
- Expiry/review date — rules based on time-sensitive infrastructure (e.g., a specific C2 IP range) must include a recommended review date

### 4.3 Rule Versioning

When the same underlying behavior is reported again in a later source (same campaign, same technique, updated artifacts), the existing rule must be updated with an incremented version rather than a new duplicate rule being created.

### 4.4 False Positive Guidance

Every rule must include false positive guidance. Rules with a high false positive risk must be labeled accordingly in metadata. The system must not ship a rule if it cannot assess false positive risk.

---

## 5. Validation Pipeline Requirements

> This is the non-negotiable gate. No IOC and no Sigma rule reaches a customer without passing validation.

### 5.1 IOC Validation

Before any IOC is included in the customer feed, it must pass:

**Static checks:**
- Value format validity (correct syntax for the declared type)
- Not on the known false-positive list (maintained and updated by the system)
- Not a private/reserved IP range, loopback, link-local, or documentation address
- Not a known-good vendor, researcher, or reference domain

**Semantic checks (AI-assisted):**
- Confirmed as genuine attacker infrastructure or tooling, not an impersonation target, victim domain, or legitimate service cited in context
- If the article describes the domain/IP as something the attacker *spoofed* or *abused as a staging platform*, the base indicator must not be included without clear attack-specific context (e.g., a specific attacker-controlled URL path, not just the hosting platform)

**Learning:**
- High-confidence false positive verdicts must be written back to the persistent false positive list so the same validation call is not repeated for future runs

### 5.2 Sigma Rule Validation

Before any Sigma rule is delivered to customers, it must pass:

**Structural validation:**
- Valid Sigma schema (parseable by standard Sigma tooling)
- Required metadata fields present and non-empty
- At least one non-empty detection condition
- MITRE ATT&CK ID in valid format

**Content validation (AI-assisted):**
- Detection conditions are specific enough to be actionable — the rule must not trigger on an entire operating system category with no discriminating artifact
- Detection conditions are grounded in the source report — no invented or generic placeholders
- False positive guidance is present and plausible

**Duplicate check:**
- New rule must not duplicate an existing rule covering the same technique, platform, and detection artifact set. If a duplicate is detected, the existing rule must be updated instead.

### 5.3 Validation Outcomes

Each item in the validation pipeline must result in one of three outcomes:

| Outcome | Meaning |
|---------|---------|
| **Pass** | Item meets all requirements; eligible for customer delivery |
| **Hold** | Item partially meets requirements; requires rule tightening or additional source corroboration before delivery |
| **Reject** | Item fails validation; logged internally; never delivered to customers |

Held items must be automatically retried in subsequent runs as new source data becomes available. The system must not silently drop held items.

---

## 6. Threat Context Requirements

The system must produce, alongside IOCs and rules, a structured threat context layer that gives customers the "so what":

### 6.1 Per-Run Briefing

Each run must produce a human-readable briefing that includes:

- **Executive summary** — 3–5 sentences suitable for a CISO or non-technical stakeholder; must name active threat actors, targeted industries/regions, and exploitation status of any CVEs
- **Threat actor tracking** — new actors first seen in this period, and returning actors active again after a gap
- **TTP summary** — new MITRE ATT&CK techniques observed, and previously seen techniques re-observed
- **Statistical summary** — counts of new and re-observed IOCs by type, new Sigma rules generated, total sources processed

### 6.2 Multi-Source Incident Correlation

When the same attack, campaign, or CVE is reported independently by multiple sources, those reports must be grouped into a single incident cluster rather than listed separately. The cluster must show:

- All contributing sources
- Consolidated IOC list (deduplicated across reports)
- Combined TTP set
- Severity derived from the highest-severity member

An indicator that appears in a multi-source cluster automatically carries higher fidelity than one from a single report.

### 6.3 Targeted Sectors and Regions

Where source reports identify targeted industry verticals or geographic regions, that context must be attached to the relevant IOCs, rules, and briefing sections.

---

## 7. Non-Functional Requirements

### 7.1 Reliability and Graceful Degradation

- If any single intelligence source is unavailable, the run must continue with the remaining sources. Source failures must be logged but must not block delivery.
- If the AI enrichment component is unavailable, the system must fall back to extraction-only mode and produce a reduced-fidelity feed rather than failing entirely. Reduced-fidelity output must be clearly labeled.
- The system must be idempotent: re-running for a date that has already been processed must not produce duplicate entries in the feed.

### 7.2 Auditability

- Every IOC in the customer feed must be traceable to its source URL(s).
- Every Sigma rule must be traceable to the source report(s) that produced its detection conditions.
- False positive decisions (both automated and manual) must be logged with rationale.
- The validation pass/hold/reject decision for every item must be recorded with timestamp and reason.

### 7.3 Configuration

The following must be configurable without code changes:

- Source list (add, remove, adjust reliability tier)
- Fidelity thresholds for feed inclusion
- Lookback window for each run
- Output formats and delivery destinations
- Known false positive lists (domains, IPs, domain suffixes)
- IOC types to include/exclude from the feed

### 7.4 Delivery

- The system must support at minimum: file-based output (JSON + Markdown), and email delivery of the daily briefing.
- IOC export must support bulk download in a format compatible with common SIEM ingestion pipelines.
- The customer-facing feed and the internal audit log must be separate outputs.

---

## 8. Acceptance Criteria

The system is considered production-ready when it can demonstrate the following over a 14-day evaluation period:

| Criterion | Target |
|-----------|--------|
| False positive rate in delivered IOC feed | < 2% (validated by manual review of a random 10% sample) |
| IOC fidelity label accuracy | ≥ 90% agreement with analyst review on fidelity assignments |
| Sigma rule structural validity | 100% of delivered rules parse without error |
| Sigma rule false positive rate | < 5% trigger rate on known-clean baseline traffic (lab environment) |
| Source coverage | ≥ 80% of configured sources successfully ingested per run |
| Run completion | ≥ 95% of scheduled runs complete within 2 hours of start |
| Traceability | 100% of delivered IOCs and rules have at least one traceable source URL |

---

## 9. Out of Scope

The following are explicitly out of scope for this system:

- Real-time (sub-hourly) feeds — daily cadence is the required baseline
- Automated blocking or firewall rule deployment — the system produces intelligence for human/downstream consumption, it does not act on it
- Vulnerability scanning or asset discovery
- Threat hunting queries (Sigma rules are for detection, not hunting)
- Manual analyst review workflow — the system must be fully automated; human review is a downstream activity

---

## 10. Prototype Reference

A working prototype implementing the core pipeline exists at `/Users/takin/projects/threats`. Engineering may use it as a behavioral reference for understanding expected inputs, outputs, and edge cases. The prototype is not a template for the production implementation — it reflects one approach, not the required approach.

Key behaviors documented in the prototype worth reviewing:

- IOC extraction and defanging logic
- False positive filtering heuristics and the auto-learning pattern
- Fidelity scoring model and the specificity assessment approach
- Sigma rule versioning and stable key design
- The validation pipeline (IOC validator and IOC researcher pass sequence)
- Tag inheritance from campaign/malware/CVE/actor context

---

*This document defines requirements. Questions about scope, prioritization, or phasing should be directed to the product owner before implementation begins.*
