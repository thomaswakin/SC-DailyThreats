"""Tests for briefing and Sigma rule generators."""

import pytest
from datetime import date, datetime, timezone
from pathlib import Path
import tempfile
import zipfile
import json

from threats.models import DailyBriefing, EnrichedIntelItem
from threats.models.ioc import IOC, IOCType
from threats.models.ttp import TTP, MITRETactic
from threats.models.threat_actor import ThreatActor
from threats.generators.sigma import generate_sigma_rules
from threats.generators.renderer import render_briefing
from threats.generators.ioc_export import generate_ioc_export


def _make_briefing() -> DailyBriefing:
    iocs = [
        IOC(type=IOCType.IP, value="185.220.101.47", confidence=0.9),
        IOC(type=IOCType.DOMAIN, value="evil-c2.com", confidence=0.9),
        IOC(type=IOCType.SHA256, value="a" * 64, confidence=0.9),
    ]
    ttps = [TTP(technique_id="T1059.001", tactic=MITRETactic.EXECUTION, name="PowerShell")]
    item = EnrichedIntelItem(
        source_name="Unit42",
        source_url="https://unit42.paloaltonetworks.com/test",
        title="APT29 Campaign Analysis",
        body="APT29 used PowerShell and C2 infrastructure",
        summary="APT29 conducted targeted espionage operation.",
        severity=0.85,
        iocs=iocs,
        ttps=ttps,
        actors=[ThreatActor(name="APT29")],
        detection_artifacts=[{
            "technique_id": "T1059.001",
            "title": "APT29 PowerShell Encoded Command Execution",
            "description": "Detects PowerShell encoded command execution used by APT29",
            "logsource_category": "process_creation",
            "logsource_product": "windows",
            "process_name": ["powershell.exe"],
            "command_line": ["-EncodedCommand", "-enc ", "-nop -w hidden"],
            "file_path": [], "registry_key": [], "network_dst_ip": [],
            "network_dst_port": [], "dns_query": [], "parent_process": [], "event_id": [],
        }],
    )
    briefing = DailyBriefing(
        briefing_date=date(2026, 3, 10),
        generated_at=datetime.now(timezone.utc),
        items=[item],
        new_iocs=iocs,
        reobserved_iocs=[],
        new_ttps=ttps,
        reobserved_ttps=[],
        new_actors=[ThreatActor(name="APT29", is_new=True)],
        executive_summary="APT29 active against energy sector.",
    )
    briefing.compute_ioc_counts()
    return briefing


class TestSigmaGenerator:
    def test_iocs_go_to_export_not_sigma(self):
        """IPs and hashes must NOT appear as standalone Sigma rules — they go to IOC export."""
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            rules = generate_sigma_rules(briefing, Path(tmpdir))
            ip_rules = [r for r in rules if "IP" in r.title]
            hash_rules = [r for r in rules if "Hash" in r.title]
            assert len(ip_rules) == 0, "IPs should go to IOC export, not Sigma rules"
            assert len(hash_rules) == 0, "Hashes should go to IOC export, not Sigma rules"

    def test_ioc_export_contains_ip_and_hash(self):
        """IP and hash IOCs must appear in the IOC export ZIP."""
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = generate_ioc_export(briefing, Path(tmpdir))
            assert zip_path is not None
            with zipfile.ZipFile(zip_path) as zf:
                json_name = [n for n in zf.namelist() if n.endswith(".json")][0]
                data = json.loads(zf.read(json_name))
            values = [i["value"] for i in data["indicators"]]
            assert "185.220.101.47" in values
            assert "a" * 64 in values

    def test_generates_artifact_rule(self):
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            rules = generate_sigma_rules(briefing, Path(tmpdir))
            artifact_rules = [r for r in rules if "T1059" in r.title or "PowerShell" in r.title]
            assert len(artifact_rules) > 0
            # Rule must contain actual detection conditions, not TODO placeholders
            assert "powershell.exe" in artifact_rules[0].yaml_content.lower()
            assert "TODO" not in artifact_rules[0].yaml_content

    def test_writes_yaml_files(self):
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            generate_sigma_rules(briefing, output_dir)
            yaml_files = list(output_dir.glob("*.yaml"))
            assert len(yaml_files) > 0


class TestRenderer:
    def test_renders_markdown(self):
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            written = render_briefing(briefing, Path(tmpdir), formats=["md"])
            assert "md" in written
            content = written["md"].read_text()
            assert "APT29" in content
            assert "Executive Summary" in content
            assert "185.220.101.47" in content

    def test_renders_json(self):
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            written = render_briefing(briefing, Path(tmpdir), formats=["json"])
            assert "json" in written
            import json
            data = json.loads(written["json"].read_text())
            assert data["briefing_date"] == "2026-03-10"
            assert len(data["items"]) == 1

    def test_output_filename_uses_date(self):
        briefing = _make_briefing()
        with tempfile.TemporaryDirectory() as tmpdir:
            written = render_briefing(briefing, Path(tmpdir), formats=["md", "json"])
            for path in written.values():
                assert "2026-03-10" in path.name
