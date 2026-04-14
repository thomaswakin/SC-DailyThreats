"""Tests for processing pipeline modules."""

import pytest
from unittest.mock import MagicMock, patch
from threats.processors.ioc_extractor import extract_iocs
from threats.processors.ttp_mapper import map_ttps
from threats.processors.deduplicator import Deduplicator
from threats.processors.ioc_researcher import IOCResearcher
from threats.models import RawIntelItem, EnrichedIntelItem
from threats.models.ioc import IOC, IOCType


class TestIOCExtractor:
    def test_extracts_ip(self):
        iocs = extract_iocs("C2 server at 185.220.101.47 seen in wild")
        ips = [i for i in iocs if i.type == IOCType.IP]
        assert any(i.value == "185.220.101.47" for i in ips)

    def test_extracts_domain(self):
        iocs = extract_iocs("Domain malicious-update.com used for C2")
        domains = [i for i in iocs if i.type == IOCType.DOMAIN]
        assert any("malicious-update.com" in i.value for i in domains)

    def test_extracts_sha256(self):
        sha256 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        iocs = extract_iocs(f"Malware hash: {sha256}")
        hashes = [i for i in iocs if i.type == IOCType.SHA256]
        assert any(i.value == sha256 for i in hashes)

    def test_defangs_iocs(self):
        iocs = extract_iocs("Domain: evil[.]com and hxxps://evil[.]com/path")
        values = [i.value for i in iocs]
        assert not any("[.]" in v for v in values)

    def test_excludes_private_ips(self):
        iocs = extract_iocs("Internal host 192.168.1.1 and 10.0.0.1")
        ips = [i for i in iocs if i.type == IOCType.IP]
        assert len(ips) == 0

    def test_excludes_common_domains(self):
        iocs = extract_iocs("Visit microsoft.com or google.com")
        domains = [i for i in iocs if i.type == IOCType.DOMAIN]
        domain_values = [i.value for i in domains]
        assert "microsoft.com" not in domain_values
        assert "google.com" not in domain_values

    def test_extracts_url(self):
        iocs = extract_iocs("Payload downloaded from https://evil.io/malware.exe")
        urls = [i for i in iocs if i.type == IOCType.URL]
        assert len(urls) > 0


class TestTTPMapper:
    def test_maps_explicit_technique_id(self):
        ttps = map_ttps("Attacker used T1059.001 to execute commands")
        ids = [t.technique_id for t in ttps]
        assert "T1059.001" in ids

    def test_maps_powershell_keyword(self):
        ttps = map_ttps("The threat actor executed PowerShell commands remotely")
        ids = [t.technique_id for t in ttps]
        assert "T1059.001" in ids

    def test_maps_ransomware_keyword(self):
        ttps = map_ttps("Files were encrypted for ransom in a ransomware attack")
        ids = [t.technique_id for t in ttps]
        assert "T1486" in ids

    def test_no_false_positives_on_empty(self):
        ttps = map_ttps("")
        assert ttps == []

    def test_deduplicates_techniques(self):
        text = "T1059.001 PowerShell T1059.001"
        ttps = map_ttps(text)
        ids = [t.technique_id for t in ttps]
        assert ids.count("T1059.001") == 1


class TestDeduplicator:
    def _make_item(self, url: str) -> RawIntelItem:
        return RawIntelItem(source_name="test", source_url=url, title="Test")

    def test_filters_seen_items(self):
        item = self._make_item("https://example.com/post-1")
        dedup = Deduplicator({item.content_hash})
        result = dedup.filter([item])
        assert len(result) == 0

    def test_passes_new_items(self):
        item = self._make_item("https://example.com/new-post")
        dedup = Deduplicator(set())
        result = dedup.filter([item])
        assert len(result) == 1

    def test_deduplicates_within_batch(self):
        item1 = self._make_item("https://example.com/post-1")
        item2 = self._make_item("https://example.com/post-1")  # duplicate
        item3 = self._make_item("https://example.com/post-2")
        dedup = Deduplicator(set())
        result = dedup.filter([item1, item2, item3])
        assert len(result) == 2


class TestIOCResearcher:
    def _make_researcher(self, verdicts: list[dict]) -> IOCResearcher:
        """Build a researcher with a mocked Anthropic client returning given verdicts."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=f'{{"verdicts": {__import__("json").dumps(verdicts)}}}')]
        mock_client.messages.create.return_value = mock_response
        limiter = MagicMock()
        limiter.acquire = MagicMock()
        return IOCResearcher(mock_client, "claude-test", limiter)

    def _make_item(self, iocs: list[IOC]) -> EnrichedIntelItem:
        item = EnrichedIntelItem(
            source_name="TestSource",
            source_url="https://example.com/report",
            title="Test APT Campaign",
            summary="Attacker used custom C2 infrastructure.",
        )
        item.iocs = iocs
        return item

    def test_sets_attack_specific_on_c2_domain(self):
        ioc = IOC(type=IOCType.DOMAIN, value="xn9f2z.xyz", confidence=0.5)
        verdicts = [{"value": "xn9f2z.xyz", "specificity": "attack_specific", "note": "DGA-pattern domain"}]
        researcher = self._make_researcher(verdicts)
        researcher.research_batch([self._make_item([ioc])])
        assert ioc.specificity == "attack_specific"
        assert ioc.specificity_note == "DGA-pattern domain"

    def test_sets_normal_on_cdn_domain(self):
        ioc = IOC(type=IOCType.DOMAIN, value="onedrive.live.com", confidence=0.5)
        verdicts = [{"value": "onedrive.live.com", "specificity": "normal", "note": "Legitimate cloud service"}]
        researcher = self._make_researcher(verdicts)
        researcher.research_batch([self._make_item([ioc])])
        assert ioc.specificity == "normal"

    def test_skips_hashes(self):
        sha = IOC(type=IOCType.SHA256, value="a" * 64, confidence=0.9)
        mock_client = MagicMock()
        limiter = MagicMock()
        limiter.acquire = MagicMock()
        researcher = IOCResearcher(mock_client, "claude-test", limiter)
        researcher.research_batch([self._make_item([sha])])
        mock_client.messages.create.assert_not_called()
        assert sha.specificity == "unknown"  # unchanged

    def test_skips_likely_fp_iocs(self):
        ioc = IOC(type=IOCType.IP, value="8.8.8.8", confidence=0.1, likely_fp=True)
        mock_client = MagicMock()
        limiter = MagicMock()
        limiter.acquire = MagicMock()
        researcher = IOCResearcher(mock_client, "claude-test", limiter)
        researcher.research_batch([self._make_item([ioc])])
        mock_client.messages.create.assert_not_called()

    def test_handles_llm_error_gracefully(self):
        ioc = IOC(type=IOCType.IP, value="185.220.101.47", confidence=0.5)
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API error")
        limiter = MagicMock()
        limiter.acquire = MagicMock()
        researcher = IOCResearcher(mock_client, "claude-test", limiter)
        # Should not raise; IOC specificity stays unknown
        researcher.research_batch([self._make_item([ioc])])
        assert ioc.specificity == "unknown"


class TestIOCTagging:
    def test_tags_cve_from_article_text(self):
        from threats.processors.llm_analyzer import _tag_iocs_from_item
        ioc = IOC(type=IOCType.IP, value="185.220.101.47", confidence=0.9)
        item = EnrichedIntelItem(
            source_name="CISA",
            source_url="https://cisa.gov/advisory",
            title="CVE-2024-12345 actively exploited",
            body="Attackers are exploiting CVE-2024-12345 and CVE-2024-99999",
        )
        item.iocs = [ioc]
        _tag_iocs_from_item(item)
        assert "CVE-2024-12345" in ioc.tags
        assert "CVE-2024-99999" in ioc.tags

    def test_tags_campaign_and_malware(self):
        from threats.processors.llm_analyzer import _tag_iocs_from_item
        from threats.models.threat_actor import ThreatActor
        ioc = IOC(type=IOCType.DOMAIN, value="evil-c2.xyz", confidence=0.9)
        item = EnrichedIntelItem(
            source_name="Mandiant",
            source_url="https://mandiant.com/report",
            title="Volt Typhoon analysis",
        )
        item.iocs = [ioc]
        item.campaign_names = ["Operation ShadowHammer"]
        item.malware_families = ["Cobalt Strike"]
        item.actors = [ThreatActor(name="APT41")]
        _tag_iocs_from_item(item)
        assert "Operation ShadowHammer" in ioc.tags
        assert "Cobalt Strike" in ioc.tags
        assert "APT41" in ioc.tags

    def test_skips_likely_fp_iocs(self):
        from threats.processors.llm_analyzer import _tag_iocs_from_item
        ioc = IOC(type=IOCType.DOMAIN, value="irs.gov", confidence=0.1, likely_fp=True)
        item = EnrichedIntelItem(
            source_name="CISA", source_url="https://cisa.gov/", title="CVE-2024-1111 phishing"
        )
        item.iocs = [ioc]
        item.campaign_names = ["Tax Season Phishing"]
        _tag_iocs_from_item(item)
        assert ioc.tags == []  # FP IOCs get no tags

    def test_tags_are_deduplicated(self):
        from threats.processors.llm_analyzer import _tag_iocs_from_item
        ioc = IOC(type=IOCType.IP, value="1.2.3.4", confidence=0.8, tags=["LockBit"])
        item = EnrichedIntelItem(
            source_name="CrowdStrike", source_url="https://crowdstrike.com/", title="LockBit campaign"
        )
        item.iocs = [ioc]
        item.malware_families = ["LockBit"]
        _tag_iocs_from_item(item)
        assert ioc.tags.count("LockBit") == 1


class TestIOCFidelityProperty:
    def test_hash_single_source_is_medium(self):
        ioc = IOC(type=IOCType.SHA256, value="a" * 64, confidence=0.5, source_count=1)
        assert ioc.fidelity == "medium"

    def test_hash_three_sources_is_high(self):
        ioc = IOC(type=IOCType.SHA256, value="a" * 64, confidence=0.5, source_count=3)
        assert ioc.fidelity == "high"

    def test_likely_fp_returns_fp(self):
        ioc = IOC(type=IOCType.IP, value="1.2.3.4", confidence=0.9, likely_fp=True)
        assert ioc.fidelity == "fp"

    def test_context_dependent_returns_low(self):
        ioc = IOC(type=IOCType.DOMAIN, value="discord.com", confidence=0.9, context_dependent=True)
        assert ioc.fidelity == "low"

    def test_normal_specificity_returns_low_even_with_high_confidence(self):
        ioc = IOC(type=IOCType.DOMAIN, value="onedrive.live.com", confidence=0.9, specificity="normal")
        assert ioc.fidelity == "low"

    def test_attack_specific_single_source_is_medium(self):
        ioc = IOC(type=IOCType.DOMAIN, value="xn9f2z.xyz", confidence=0.4, source_count=1, specificity="attack_specific")
        assert ioc.fidelity == "medium"

    def test_attack_specific_two_sources_is_high(self):
        ioc = IOC(type=IOCType.IP, value="185.220.101.47", confidence=0.7, source_count=2, specificity="attack_specific")
        assert ioc.fidelity == "high"

    def test_three_sources_is_high(self):
        ioc = IOC(type=IOCType.IP, value="185.220.101.47", confidence=0.5, source_count=3)
        assert ioc.fidelity == "high"

    def test_low_confidence_single_source_unknown_is_low(self):
        ioc = IOC(type=IOCType.DOMAIN, value="some-domain.com", confidence=0.4, source_count=1)
        assert ioc.fidelity == "low"
