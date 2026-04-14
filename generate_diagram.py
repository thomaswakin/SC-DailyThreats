"""Generate the Threat Intel Pipeline data flow diagram as a PDF."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.lines import Line2D
import numpy as np

# ── Colour palette ────────────────────────────────────────────────────────────
C_STATIC   = "#2D6A9F"   # blue  – static / deterministic steps
C_AI       = "#7B2D8B"   # purple – AI-driven steps
C_STORE    = "#1A7A4A"   # green  – persistent stores / outputs
C_OUTPUT   = "#C05C00"   # orange – customer-facing outputs
C_FEEDBACK = "#A0001E"   # red    – feedback loops

BG         = "#F7F8FA"
EDGE_COLOR = "#333333"

ALPHA_BOX  = 0.93

# ── Figure setup ──────────────────────────────────────────────────────────────
fig = plt.figure(figsize=(22, 30), facecolor=BG)
ax  = fig.add_axes([0, 0, 1, 1], facecolor=BG)
ax.set_xlim(0, 22)
ax.set_ylim(0, 30)
ax.axis("off")

# ── Helper functions ──────────────────────────────────────────────────────────

def box(ax, x, y, w, h, label, sublabel="", color=C_STATIC, fontsize=9.5, icon=""):
    """Draw a rounded rectangle with label."""
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.07",
        linewidth=1.4,
        edgecolor=EDGE_COLOR,
        facecolor=color,
        alpha=ALPHA_BOX,
        zorder=3,
    )
    ax.add_patch(rect)
    cx, cy = x + w / 2, y + h / 2
    full = (f"{icon}  {label}" if icon else label).strip()
    ax.text(cx, cy + (0.12 if sublabel else 0), full,
            ha="center", va="center", fontsize=fontsize,
            fontweight="bold", color="white", zorder=4, wrap=False)
    if sublabel:
        ax.text(cx, cy - 0.22, sublabel,
                ha="center", va="center", fontsize=7.5,
                color="white", alpha=0.88, zorder=4, style="italic")

def arrow(ax, x1, y1, x2, y2, color=EDGE_COLOR, lw=1.6, style="->",
          label="", label_color=EDGE_COLOR, dashed=False):
    """Draw a simple annotated arrow."""
    ls = (0, (4, 3)) if dashed else "solid"
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle=style, color=color,
                        lw=lw, linestyle=ls,
                        connectionstyle="arc3,rad=0.0"),
        zorder=2,
    )
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx + 0.08, my, label, fontsize=7.2, color=label_color,
                va="center", ha="left", zorder=5,
                bbox=dict(facecolor=BG, edgecolor="none", alpha=0.7, pad=1))

def curved_arrow(ax, x1, y1, x2, y2, rad=0.25, color=C_FEEDBACK, lw=1.5,
                 label="", dashed=True):
    ls = (0, (4, 3)) if dashed else "solid"
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle="->", color=color, lw=lw, linestyle=ls,
                        connectionstyle=f"arc3,rad={rad}"),
        zorder=2,
    )
    if label:
        mx = (x1 + x2) / 2 + (0.5 if rad > 0 else -0.5)
        my = (y1 + y2) / 2
        ax.text(mx, my, label, fontsize=7.0, color=color, va="center",
                ha="center", zorder=5, style="italic",
                bbox=dict(facecolor=BG, edgecolor="none", alpha=0.8, pad=1))

def section_label(ax, x, y, text):
    ax.text(x, y, text, fontsize=8, color="#555555", ha="left", va="center",
            style="italic", zorder=5)

def divider(ax, y, label=""):
    ax.axhline(y, color="#CCCCCC", lw=0.8, linestyle="--", zorder=1)
    if label:
        ax.text(0.25, y + 0.1, label, fontsize=7.5, color="#888888",
                ha="left", va="bottom", style="italic")

# ══════════════════════════════════════════════════════════════════════════════
# TITLE
# ══════════════════════════════════════════════════════════════════════════════
ax.text(11, 29.4, "Threat Intelligence Agent — Data Flow",
        ha="center", va="center", fontsize=18, fontweight="bold", color="#1A1A2E")
ax.text(11, 28.95, "Static (deterministic) vs. AI-driven operations · Feedback loops shown in red",
        ha="center", va="center", fontsize=10, color="#555555")

# ══════════════════════════════════════════════════════════════════════════════
# LEGEND
# ══════════════════════════════════════════════════════════════════════════════
legend_items = [
    mpatches.Patch(facecolor=C_STATIC,   edgecolor=EDGE_COLOR, label="Static / Deterministic"),
    mpatches.Patch(facecolor=C_AI,       edgecolor=EDGE_COLOR, label="AI Agent (LLM)"),
    mpatches.Patch(facecolor=C_STORE,    edgecolor=EDGE_COLOR, label="Persistent Store / Database"),
    mpatches.Patch(facecolor=C_OUTPUT,   edgecolor=EDGE_COLOR, label="Customer-Facing Output"),
    Line2D([0], [0], color=EDGE_COLOR, lw=1.8,          label="Data flow"),
    Line2D([0], [0], color=C_FEEDBACK, lw=1.5, dashes=(4,3), label="AI Feedback Loop"),
]
ax.legend(handles=legend_items, loc="upper left",
          bbox_to_anchor=(0.01, 0.985), framealpha=0.92,
          fontsize=8.5, title="Legend", title_fontsize=8.5,
          edgecolor="#AAAAAA", facecolor="white",
          ncol=3, columnspacing=1.2)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — COLLECTION  (y ≈ 26–28.2)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 28.3, "PHASE 1 · COLLECTION")

# Source groups (left cluster)
src_boxes = [
    (0.4, 27.3, 2.8, 0.7, "Vendor Blogs", "Mandiant · CrowdStrike · Unit42 · Talos …"),
    (0.4, 26.4, 2.8, 0.7, "Gov Advisories", "CISA · NCSC · FBI Flash"),
    (0.4, 25.5, 2.8, 0.7, "OSINT Feeds", "OTX · ThreatFox · URLhaus · CISA KEV"),
    (0.4, 24.6, 2.8, 0.7, "IR Reports", "DFIR Report · Red Canary"),
]
for x, y, w, h, lbl, sub in src_boxes:
    box(ax, x, y, w, h, lbl, sub, color=C_STATIC, fontsize=8.5)

# Collector box
box(ax, 4.2, 25.6, 3.0, 1.3, "RSS / Scraper / API\nCollectors",
    "HTTP fetch · rate-limited · per-source", color=C_STATIC, fontsize=9)

# Arrows: sources → collector
for _, y, _, h, _, _ in src_boxes:
    arrow(ax, 3.2, y + h/2, 4.2, 26.25, color=EDGE_COLOR, lw=1.2)

# Dedup box
box(ax, 8.2, 25.6, 2.8, 1.3, "Deduplication",
    "SHA-256 content hash\nagainst seen_hashes DB", color=C_STATIC, fontsize=9)
arrow(ax, 7.2, 26.25, 8.2, 26.25, color=EDGE_COLOR, label="raw items")

# Seen-hashes DB
box(ax, 8.2, 24.2, 2.8, 0.8, "seen_hashes DB", "intel_items table", color=C_STORE, fontsize=8.5)
arrow(ax, 9.6, 25.6, 9.6, 25.0, color=EDGE_COLOR, lw=1.2, label=" dedup check")

# Static IOC/TTP extractor
box(ax, 12.1, 25.6, 3.2, 1.3, "IOC + TTP Extractor",
    "Regex · defang · private-IP filter\nFP config exclusions", color=C_STATIC, fontsize=9)
arrow(ax, 11.0, 26.25, 12.1, 26.25, color=EDGE_COLOR, label="new items")

# false_positives.yaml (static config read)
box(ax, 12.1, 24.2, 3.2, 0.8, "false_positives.yaml", "static exclusion list", color=C_STORE, fontsize=8.5)
arrow(ax, 13.7, 25.6, 13.7, 25.0, color=EDGE_COLOR, lw=1.2, label=" load FP config")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — AI ENRICHMENT  (y ≈ 20–24.5)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 24.2, "PHASE 2 · AI ENRICHMENT")

# Flow: extractor → LLM Enrichment
box(ax, 4.2, 22.0, 3.4, 1.4, "LLM Enrichment",
    "Summary · Severity · Actors · TTPs\nCampaign names · Malware families\nDetection artifacts · FP flags",
    color=C_AI, fontsize=8.5)

arrow(ax, 15.3, 26.25, 16.2, 26.25, color=EDGE_COLOR, lw=1.2)  # extractor → right
arrow(ax, 16.2, 26.25, 16.2, 23.0, color=EDGE_COLOR, lw=1.2)   # down
arrow(ax, 16.2, 23.0, 7.6, 22.7, color=EDGE_COLOR, lw=1.2, label="extracted items + IOCs")

# IOC Validator
box(ax, 4.2, 20.3, 3.4, 1.4, "IOC Validator",
    "Genuine vs. FP verdict\nConfidence adjustment\nAuto-learn high-conf FPs",
    color=C_AI, fontsize=8.5)
arrow(ax, 5.9, 22.0, 5.9, 21.7, color=EDGE_COLOR, label=" enriched items")

# IOC Researcher
box(ax, 4.2, 18.6, 3.4, 1.4, "IOC Researcher",
    "Attack-specific vs. normal activity\nSpecificity verdict + note\nFidelity signal for non-hashes",
    color=C_AI, fontsize=8.5)
arrow(ax, 5.9, 20.3, 5.9, 20.0, color=EDGE_COLOR, label=" validated IOCs")

# ── AI Feedback: validator → false_positives.yaml ─────────────────────────
curved_arrow(ax, 4.2, 21.0, 4.0, 24.55, rad=-0.45, color=C_FEEDBACK,
             label=" auto-learn FP\n (conf ≥ 0.85)")

# Tagger (static+AI hybrid)
box(ax, 4.2, 16.9, 3.4, 1.4, "IOC Tagger",
    "CVE regex (static)\nCampaign · Malware family · Actor\nfrom LLM enrichment output",
    color=C_AI, fontsize=8.5)
arrow(ax, 5.9, 18.6, 5.9, 18.3, color=EDGE_COLOR, label=" specificity set")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — STORAGE  (y ≈ 14–16.5)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 16.7, "PHASE 3 · STORAGE")

box(ax, 2.6, 14.8, 5.8, 1.5, "SQLite Database  (store_enriched_batch)",
    "intel_items · iocs (type, value, confidence, specificity, specificity_note, tags)\n"
    "ttps · threat_actors · item_iocs · item_ttps · item_actors · run_log · sigma_rule_registry",
    color=C_STORE, fontsize=8.5)
arrow(ax, 5.9, 16.9, 5.9, 16.3, color=EDGE_COLOR, label=" tagged items + IOCs")

# Clusterer
box(ax, 9.5, 15.2, 3.5, 1.0, "Incident Clusterer",
    "Groups related items by campaign / overlap\nMulti-source → incident_clusters table",
    color=C_STATIC, fontsize=8.5)
arrow(ax, 8.4, 15.55, 9.5, 15.7, color=EDGE_COLOR, label="  stored items")

# Feedback: clusterer → DB
arrow(ax, 9.5, 15.7, 8.4, 15.35, color=C_FEEDBACK, lw=1.4, dashed=True,
      label=" cluster IDs\n written back")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — BRIEFING ASSEMBLY  (y ≈ 11–14)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 14.5, "PHASE 4 · BRIEFING ASSEMBLY")

box(ax, 2.6, 12.1, 3.4, 1.5, "Briefing Builder",
    "Queries new + re-observed IOCs\nComputes source_count per IOC\nAssembles DailyBriefing model",
    color=C_STATIC, fontsize=8.5)
arrow(ax, 5.5, 14.8, 5.5, 13.6, color=EDGE_COLOR, label="  DB query")

box(ax, 7.0, 12.1, 3.4, 1.5, "Executive Summary\nGenerator",
    "CISO-level 3–5 sentence prose\nRanks by severity", color=C_AI, fontsize=8.5)
arrow(ax, 6.0, 12.85, 7.0, 12.85, color=EDGE_COLOR, label=" top items")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — SIGMA RULE GENERATION  (y ≈ 8–11.5)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 11.8, "PHASE 5 · SIGMA RULE GENERATION")

box(ax, 2.6, 9.5, 3.4, 1.5, "Sigma Generator",
    "Behavioral rules from detection artifacts\nJinja2 templates · context-dependent\nIOC bundles",
    color=C_STATIC, fontsize=8.5)
arrow(ax, 4.3, 12.1, 4.3, 11.0, color=EDGE_COLOR, label=" briefing + items")

box(ax, 2.6, 7.7, 3.4, 1.5, "Sigma Reviewer",
    "Tightens detection conditions\nAdds expiry metadata\nFP risk label",
    color=C_AI, fontsize=8.5)
arrow(ax, 4.3, 9.5, 4.3, 9.2, color=EDGE_COLOR, label=" draft rules")

# Sigma rule registry
box(ax, 7.2, 9.2, 3.4, 1.2, "Sigma Rule Registry",
    "Stable key · version counter\nPrevents duplicate rules", color=C_STORE, fontsize=8.5)
arrow(ax, 6.0, 10.25, 7.2, 9.8, color=EDGE_COLOR, label=" version check")

# Feedback: registry → generator (version bump)
curved_arrow(ax, 7.2, 9.8, 6.0, 10.6, rad=0.3, color=C_FEEDBACK,
             label=" version bump\n or new rule ID")

# Feedback: reviewer → registry (update after review)
curved_arrow(ax, 6.0, 8.5, 7.2, 9.2, rad=-0.3, color=C_FEEDBACK,
             label=" reviewed rule\n written back")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — VALIDATION GATE  (y ≈ 4.5–7.5)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 7.5, "PHASE 6 · VALIDATION GATE  (nothing ships without passing)")

# IOC gate
box(ax, 1.0, 5.5, 3.8, 1.5, "IOC Validation Gate",
    "Static: format, private-IP, FP list\nAI: genuine vs impersonation target\nvs legitimate-service check",
    color=C_AI, fontsize=8.5)
arrow(ax, 4.3, 7.7, 4.3, 7.0, color=EDGE_COLOR, label=" reviewed rules")
arrow(ax, 3.0, 12.1, 1.5, 12.1, color=EDGE_COLOR, lw=1.0)
arrow(ax, 1.5, 12.1, 1.5, 7.0, color=EDGE_COLOR, lw=1.0)
arrow(ax, 1.5, 7.0, 1.8, 7.0, color=EDGE_COLOR, lw=1.0, label=" IOCs from briefing")

# Sigma gate
box(ax, 5.6, 5.5, 3.8, 1.5, "Sigma Rule\nValidation Gate",
    "Structural: schema parse · required fields\nContent: grounded artifacts · no generics\nDuplicate: dedup vs registry",
    color=C_AI, fontsize=8.5)
arrow(ax, 4.3, 7.7, 5.6, 7.0, color=EDGE_COLOR, lw=1.0)
arrow(ax, 5.8, 7.0, 6.0, 7.0, color=EDGE_COLOR, lw=1.0, label="  rules")

# Pass / Hold / Reject
box(ax, 2.0, 3.8, 1.6, 1.0, "PASS", color="#1A7A4A", fontsize=10)
box(ax, 3.9, 3.8, 1.6, 1.0, "HOLD", color="#8B6914", fontsize=10)
box(ax, 5.8, 3.8, 1.6, 1.0, "REJECT", color="#8B1A1A", fontsize=10)

arrow(ax, 2.4, 5.5, 2.4, 4.8, color=EDGE_COLOR)
arrow(ax, 3.2, 5.5, 3.2, 4.8, color=EDGE_COLOR)  # hold from IOC gate
arrow(ax, 6.5, 5.5, 6.5, 4.8, color=EDGE_COLOR)

arrow(ax, 2.8, 5.5, 4.7, 4.8, color="#8B6914", lw=1.2)   # hold path
arrow(ax, 7.2, 5.5, 6.6, 4.8, color="#8B1A1A", lw=1.2)    # reject path

# Hold feedback: retry on next run
curved_arrow(ax, 3.9, 3.8, 9.6, 14.8, rad=0.18, color=C_FEEDBACK,
             label=" HOLD: retry on\n next run cycle")

# Reject → internal audit log
box(ax, 9.5, 3.5, 3.0, 0.9, "Internal Audit Log", "reject reason · timestamp · traceability", color=C_STORE, fontsize=8)
arrow(ax, 6.6, 3.8, 9.5, 3.95, color="#8B1A1A", lw=1.2, dashed=True, label=" logged, not shipped")

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — OUTPUTS  (y ≈ 1–3.5)
# ══════════════════════════════════════════════════════════════════════════════
divider(ax, 3.6, "PHASE 7 · CUSTOMER-FACING OUTPUTS")

outputs = [
    (0.5,  1.4, 2.8, 1.0, "Daily Briefing\nMarkdown + JSON", "Per-IOC fidelity · tags\nspecificity notes · actors"),
    (3.6,  1.4, 2.8, 1.0, "IOC Export ZIP", "By type · machine-readable\nJSON / STIX-ready"),
    (6.7,  1.4, 2.8, 1.0, "Sigma Rules\n(YAML files)", "Versioned · ATT&CK mapped\nexpiry metadata"),
    (9.8,  1.4, 2.8, 1.0, "Email Briefing", "to: · cc: recipients\nSMTP delivery"),
]
for x, y, w, h, lbl, sub in outputs:
    box(ax, x, y, w, h, lbl, sub, color=C_OUTPUT, fontsize=8.5)

# Arrows from PASS → outputs
arrow(ax, 2.8, 3.8, 1.9, 2.4, color="#1A7A4A", lw=1.5)
arrow(ax, 2.8, 3.8, 5.0, 2.4, color="#1A7A4A", lw=1.5)
arrow(ax, 7.5, 5.5, 8.1, 2.4, color="#1A7A4A", lw=1.5)
arrow(ax, 2.8, 3.8, 11.2, 2.4, color="#1A7A4A", lw=1.5)

# ══════════════════════════════════════════════════════════════════════════════
# RIGHT-SIDE ANNOTATIONS — highlight AI feedback loops
# ══════════════════════════════════════════════════════════════════════════════

# Vertical feedback annotation box (right margin)
fb_box = FancyBboxPatch(
    (14.8, 7.0), 6.8, 11.2,
    boxstyle="round,pad=0.15",
    linewidth=1.2,
    edgecolor=C_FEEDBACK,
    facecolor="#FFF5F5",
    alpha=0.88,
    zorder=1,
)
ax.add_patch(fb_box)

ax.text(18.2, 18.4, "AI Feedback Loops", ha="center", va="center",
        fontsize=11, fontweight="bold", color=C_FEEDBACK)

loops = [
    ("1  IOC Validator → false_positives.yaml",
     "High-confidence (≥ 0.85) FP verdicts are\nappended to the static exclusion config.\nSame FP not re-evaluated in future runs."),
    ("2  IOC Researcher → iocs.specificity",
     "Attack-specificity verdict + note persisted\nper IOC. Union-merged across runs so each\nnew sighting refines the assessment."),
    ("3  IOC Tags → iocs.tags",
     "CVE IDs, campaign names, malware families,\nand actor names from each article are merged\ninto the IOC's tag set across all runs."),
    ("4  Sigma Reviewer → sigma_rule_registry",
     "Reviewed rule written back with version bump.\nStable rule ID preserved. Subsequent runs\nupdate existing rules rather than duplicating."),
    ("5  Validation HOLD → next run retry",
     "Items that pass static checks but fail\nsemantic validation are queued and\nautomatically retried as new sources arrive."),
    ("6  Clusterer → incident_clusters table",
     "Multi-source matches written back to DB.\nSubsequent IOC queries include cluster context,\nboosting source_count for affected IOCs."),
]

y_pos = 17.8
for title, desc in loops:
    ax.text(15.2, y_pos, f"► {title}", fontsize=8.5, fontweight="bold",
            color=C_FEEDBACK, va="top")
    ax.text(15.5, y_pos - 0.28, desc, fontsize=7.8, color="#333333",
            va="top", linespacing=1.4)
    y_pos -= 1.72

# ══════════════════════════════════════════════════════════════════════════════
# RIGHT-SIDE — Phase colour key (repeat inline for readability)
# ══════════════════════════════════════════════════════════════════════════════
phase_box = FancyBboxPatch(
    (14.8, 20.0), 6.8, 7.8,
    boxstyle="round,pad=0.15",
    linewidth=1.0,
    edgecolor="#AAAAAA",
    facecolor="white",
    alpha=0.90,
    zorder=1,
)
ax.add_patch(phase_box)
ax.text(18.2, 27.95, "Step-by-Step Summary", ha="center", fontsize=11,
        fontweight="bold", color="#1A1A2E")

steps = [
    (C_STATIC, "1. Collection",      "HTTP fetch from 25+ configured sources\n(RSS · scrapers · OTX API)"),
    (C_STATIC, "2. Deduplication",   "SHA-256 hash vs. seen_hashes DB.\nNew items only proceed."),
    (C_STATIC, "3. IOC / TTP Extract","Regex patterns · defang · private-IP\nfilter · false_positives.yaml exclusion"),
    (C_AI,     "4. LLM Enrichment",  "Summary · severity · actors · TTPs\nCampaign · malware · detection artifacts\nFP IOC flagging"),
    (C_AI,     "5. IOC Validator",   "Genuine vs. FP per-article pass.\nAuto-learns high-confidence FPs."),
    (C_AI,     "6. IOC Researcher",  "Attack-specific vs. normal activity.\nSpecificity + note persisted to DB."),
    (C_AI,     "7. IOC Tagger",      "CVE (regex) + campaign + malware +\nactor → merged tag set per IOC"),
    (C_STORE,  "8. Storage",         "All items, IOCs, TTPs, actors, clusters\nwritten to SQLite"),
    (C_STATIC, "9. Briefing Build",  "Query new + re-observed IOCs.\nCompute source_count. Assemble model."),
    (C_AI,     "10. Exec Summary",   "CISO-level prose generated by LLM."),
    (C_STATIC, "11. Sigma Generate", "Jinja2 templates from detection artifacts.\nVersioned via registry."),
    (C_AI,     "12. Sigma Review",   "Tighten conditions · FP risk · expiry."),
    (C_AI,     "13. Validation Gate","IOC + Sigma: static checks then AI\nsemantic review. Pass / Hold / Reject."),
    (C_OUTPUT, "14. Deliver",        "Markdown · JSON · Sigma YAML · Email"),
]

y_s = 27.55
for color, title, desc in steps:
    dot = FancyBboxPatch((15.0, y_s - 0.08), 0.25, 0.28,
                         boxstyle="round,pad=0.02",
                         facecolor=color, edgecolor="none", zorder=4)
    ax.add_patch(dot)
    ax.text(15.45, y_s + 0.06, title, fontsize=8.2, fontweight="bold",
            color=color, va="center")
    ax.text(15.45, y_s - 0.25, desc, fontsize=7.2, color="#444444",
            va="top", linespacing=1.3)
    y_s -= 0.52

# ══════════════════════════════════════════════════════════════════════════════
# Footer
# ══════════════════════════════════════════════════════════════════════════════
ax.text(11, 0.35, "Threat Intelligence Agent · Data Flow Diagram · 2026-04-03  "
        "· Static steps in blue · AI-driven steps in purple · Feedback loops in red",
        ha="center", va="center", fontsize=7.5, color="#888888")

# ── Save ──────────────────────────────────────────────────────────────────────
out = "data/threat_intel_dataflow.pdf"
import os; os.makedirs("data", exist_ok=True)
fig.savefig(out, format="pdf", bbox_inches="tight", dpi=180,
            facecolor=BG, edgecolor="none")
print(f"Saved: {out}")
plt.close(fig)
