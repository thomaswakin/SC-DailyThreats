"""AlienVault OTX API collector."""

import logging
import os
from datetime import datetime, timezone

from threats.models import RawIntelItem
from threats.utils.http import get_session
from .base import BaseCollector

log = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com"


class OTXCollector(BaseCollector):
    """Collects subscribed pulses from AlienVault OTX."""

    def collect(self) -> list[RawIntelItem]:
        api_key = os.getenv("OTX_API_KEY", "").strip()
        if not api_key:
            log.info("OTX_API_KEY not set - skipping OTX collection")
            return []

        log.info("Collecting OTX pulses")
        session = get_session()
        session.headers["X-OTX-API-KEY"] = api_key

        items: list[RawIntelItem] = []
        url = f"{OTX_BASE}/api/v1/pulses/subscribed"
        params: dict = {"limit": 50, "page": 1}

        try:
            while url:
                resp = session.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
                for pulse in data.get("results", []):
                    items.append(self._pulse_to_item(pulse))
                url = data.get("next")  # pagination
                params = {}             # next URL already has params
                if len(items) >= 200:
                    break
        except Exception as exc:
            log.error("OTX collection error: %s", exc)

        log.info("  -> %d pulses from OTX", len(items))
        return items

    def _pulse_to_item(self, pulse: dict) -> RawIntelItem:
        ioc_summary = self._summarize_indicators(pulse.get("indicators", []))
        body = "\n".join(filter(None, [
            pulse.get("description", ""),
            f"TLP: {pulse.get('tlp', 'white').upper()}",
            f"Tags: {', '.join(pulse.get('tags', []))}",
            f"Malware Families: {', '.join(m.get('display_name', '') for m in pulse.get('malware_families', []))}",
            f"Targeted Countries: {', '.join(pulse.get('targeted_countries', []))}",
            ioc_summary,
        ]))

        return RawIntelItem(
            source_name="AlienVault OTX",
            source_url=f"{OTX_BASE}/pulse/{pulse.get('id', '')}",
            title=pulse.get("name", "OTX Pulse"),
            body=body,
            published_at=self._parse_dt(pulse.get("created")),
            tags=pulse.get("tags", []) + self.tags,
        )

    def _summarize_indicators(self, indicators: list[dict]) -> str:
        if not indicators:
            return ""
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for ind in indicators:
            t = ind.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
            if len(samples.get(t, [])) < 3:
                samples.setdefault(t, []).append(ind.get("indicator", ""))
        lines = []
        for t, count in counts.items():
            ex = ", ".join(samples[t])
            lines.append(f"  {t}: {count} (e.g. {ex})")
        return "Indicators:\n" + "\n".join(lines)

    def _parse_dt(self, value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
