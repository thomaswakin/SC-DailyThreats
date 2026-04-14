"""Export IOCs as a structured CSV + JSON bundle with fidelity, FP flags, and expiry."""

from __future__ import annotations
import csv
import io
import json
import logging
import zipfile
from datetime import date, timedelta
from pathlib import Path

from threats.models import DailyBriefing
from threats.models.ioc import IOC, IOCType

log = logging.getLogger(__name__)

_HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}

# Default expiry by IOC type (days). None = no expiry.
_EXPIRY_DAYS: dict[str, int | None] = {
    IOCType.MD5.value:     None,   # hashes: no expiry — the binary doesn't change
    IOCType.SHA1.value:    None,
    IOCType.SHA256.value:  None,
    IOCType.IP.value:      90,     # single-source IP; boosted to 180 for multi-source
    IOCType.DOMAIN.value:  60,     # single-source domain; boosted to 90 for multi-source
    IOCType.URL.value:     30,
    IOCType.EMAIL.value:   90,
    IOCType.FILENAME.value: 180,
    IOCType.REGISTRY.value: 365,
}
_CONTEXT_DEPENDENT_EXPIRY = 30     # context-dependent IOCs age out faster


def _fidelity(ioc: IOC) -> str:
    """Compute HIGH / MEDIUM / LOW fidelity for an IOC."""
    if ioc.context_dependent:
        return "low"
    if ioc.type in _HASH_TYPES:
        return "high"   # cryptographic fingerprints are always high fidelity
    if ioc.source_count >= 2 and ioc.confidence >= 0.7:
        return "high"
    if ioc.confidence >= 0.7 or ioc.source_count >= 2:
        return "medium"
    return "low"


def _expiry_date(ioc: IOC, as_of: date) -> str | None:
    """Return ISO expiry date string, or None if no expiry."""
    if ioc.context_dependent:
        return (as_of + timedelta(days=_CONTEXT_DEPENDENT_EXPIRY)).isoformat()
    base_days = _EXPIRY_DAYS.get(ioc.type.value)
    if base_days is None:
        return None
    # Multi-source IOCs last longer
    if ioc.type == IOCType.IP and ioc.source_count >= 2:
        base_days = 180
    elif ioc.type == IOCType.DOMAIN and ioc.source_count >= 2:
        base_days = 90
    return (as_of + timedelta(days=base_days)).isoformat()


def _fp_risk_label(ioc: IOC) -> str:
    if ioc.likely_fp:
        return "suppress"           # Should not be used; kept for transparency
    if ioc.context_dependent:
        return "context-dependent"  # Use only with corroborating indicators
    return "clean"


def _ioc_to_dict(ioc: IOC, as_of: date) -> dict:
    return {
        "type":             ioc.type.value,
        "value":            ioc.value,
        "fidelity":         _fidelity(ioc),
        "fp_risk":          _fp_risk_label(ioc),
        "context_dependent": ioc.context_dependent,
        "confidence":       round(ioc.confidence, 3),
        "source_count":     ioc.source_count,
        "first_seen":       ioc.first_seen.strftime("%Y-%m-%d") if ioc.first_seen else "",
        "last_seen":        ioc.last_seen.strftime("%Y-%m-%d") if ioc.last_seen else "",
        "expiry_date":      _expiry_date(ioc, as_of) or "",
    }


def generate_ioc_export(briefing: DailyBriefing, output_dir: Path) -> Path | None:
    """
    Generate ioc_indicators_YYYY-MM-DD.zip containing:
      - iocs_YYYY-MM-DD.csv   (all non-suppressed IOCs)
      - iocs_YYYY-MM-DD.json  (same data, structured)

    Excludes likely_fp IOCs. Includes context_dependent with fp_risk label.
    Returns the path to the ZIP, or None if no IOCs.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    as_of = briefing.briefing_date

    # Combine new + re-observed; exclude hard FPs
    all_iocs = [i for i in briefing.new_iocs + briefing.reobserved_iocs if not i.likely_fp]
    if not all_iocs:
        log.info("IOC export: no IOCs to export")
        return None

    # Sort: fidelity desc, type, value
    fidelity_order = {"high": 0, "medium": 1, "low": 2}
    all_iocs.sort(key=lambda i: (fidelity_order.get(_fidelity(i), 3), i.type.value, i.value))

    rows = [_ioc_to_dict(i, as_of) for i in all_iocs]
    date_str = as_of.isoformat()

    # Build CSV in memory
    csv_buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(csv_buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    csv_bytes = csv_buf.getvalue().encode("utf-8")

    # Build JSON in memory
    json_payload = {
        "generated_date": date_str,
        "total_iocs": len(rows),
        "by_fidelity": {
            "high":   sum(1 for r in rows if r["fidelity"] == "high"),
            "medium": sum(1 for r in rows if r["fidelity"] == "medium"),
            "low":    sum(1 for r in rows if r["fidelity"] == "low"),
        },
        "indicators": rows,
    }
    json_bytes = json.dumps(json_payload, indent=2).encode("utf-8")

    # Write ZIP
    zip_path = output_dir / f"ioc_indicators_{date_str}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"iocs_{date_str}.csv",  csv_bytes)
        zf.writestr(f"iocs_{date_str}.json", json_bytes)

    log.info(
        "IOC export: %d indicators → %s (high:%d medium:%d low:%d)",
        len(rows),
        zip_path,
        json_payload["by_fidelity"]["high"],
        json_payload["by_fidelity"]["medium"],
        json_payload["by_fidelity"]["low"],
    )
    return zip_path
