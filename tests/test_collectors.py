"""Tests for collectors using mocked HTTP responses."""

import json
import pytest
import responses as resp_mock
from unittest.mock import MagicMock, patch
from threats.collectors.rss import RSSCollector
from threats.collectors.scraper import ScraperCollector
from threats.collectors.source_discovery import SourceDiscovery, _domain, _dedup_by_domain


@pytest.fixture(autouse=True)
def reset_http_session():
    """Reset the shared session between tests."""
    import threats.utils.http as http_mod
    http_mod._session = None
    yield
    http_mod._session = None


class TestRSSCollector:
    @resp_mock.activate
    def test_collect_returns_items(self, sample_rss_xml):
        resp_mock.add(
            resp_mock.GET,
            "https://test-feed.example.com/rss",
            body=sample_rss_xml,
            content_type="application/rss+xml",
        )
        config = {
            "name": "Test Feed",
            "url": "https://test-feed.example.com/rss",
            "reliability": "high",
            "tags": ["test"],
        }
        collector = RSSCollector(config)
        items = collector.collect()
        assert len(items) == 2
        assert items[0].source_name == "Test Feed"
        assert "APT29" in items[0].title

    @resp_mock.activate
    def test_collect_handles_network_error(self):
        resp_mock.add(
            resp_mock.GET,
            "https://test-feed.example.com/rss",
            body=Exception("Connection refused"),
        )
        config = {"name": "Bad Feed", "url": "https://test-feed.example.com/rss", "tags": []}
        collector = RSSCollector(config)
        items = collector.collect()
        assert items == []

    def test_collect_skips_missing_url(self):
        config = {"name": "No URL Feed", "url": None, "tags": []}
        collector = RSSCollector(config)
        items = collector.collect()
        assert items == []


class TestSourceDiscovery:
    """Unit tests for the source discovery module."""

    def _make_discovery(self, repo=None, feeds_path=None, llm_verdicts=None, tmp_path=None):
        """Build a SourceDiscovery with mocked dependencies."""
        import tempfile, pathlib, yaml

        if tmp_path is None:
            tmp_path = pathlib.Path(tempfile.mkdtemp())

        # Minimal feeds.yaml
        fp = tmp_path / "feeds.yaml"
        fp.write_text("feeds:\n  - name: Existing\n    url: https://existing.com/feed/\n", encoding="utf-8")

        if repo is None:
            repo = MagicMock()
            repo.get_known_candidate_urls.return_value = set()
            repo.get_cited_domains.return_value = []
            repo.upsert_source_candidate = MagicMock()

        mock_client = MagicMock()
        if llm_verdicts is not None:
            mock_response = MagicMock()
            mock_response.content = [MagicMock(text=json.dumps(llm_verdicts))]
            mock_client.messages.create.return_value = mock_response

        limiter = MagicMock()
        limiter.acquire = MagicMock()

        return SourceDiscovery(
            repo=repo,
            feeds_path=fp,
            llm_client=mock_client,
            model="claude-test",
            limiter=limiter,
        )

    def test_domain_helper(self):
        assert _domain("https://www.elastic.co/security-labs/rss") == "elastic.co"
        assert _domain("https://unit42.paloaltonetworks.com/feed/") == "unit42.paloaltonetworks.com"
        assert _domain("https://www.mandiant.com/blog/rss") == "mandiant.com"
        assert _domain("not-a-url") == ""

    def test_dedup_by_domain_keeps_first(self):
        candidates = [
            {"url": "https://blog.a.com/feed", "domain": "a.com"},
            {"url": "https://a.com/rss", "domain": "a.com"},   # duplicate domain
            {"url": "https://b.com/feed", "domain": "b.com"},
        ]
        result = _dedup_by_domain(candidates)
        assert len(result) == 2
        assert result[0]["url"] == "https://blog.a.com/feed"

    def test_parse_markdown_urls_extracts_links(self):
        disc = self._make_discovery()
        md = "Check out [Elastic](https://elastic.co/blog) and [Unit42](https://unit42.io/feed)"
        urls = disc._parse_markdown_urls(md)
        assert "https://elastic.co/blog" in urls
        assert "https://unit42.io/feed" in urls

    def test_parse_misp_json_extracts_urls(self):
        disc = self._make_discovery()
        data = json.dumps([
            {"url": "https://threatfox.abuse.ch/export/json/", "name": "ThreatFox"},
            {"url": "https://urlhaus.abuse.ch/feeds/", "name": "URLhaus"},
        ])
        urls = disc._parse_misp_json(data)
        assert "https://threatfox.abuse.ch/export/json/" in urls

    def test_existing_feed_domains_skipped(self):
        """Domains already in feeds.yaml must not become candidates."""
        disc = self._make_discovery()
        existing = disc._existing_feed_domains()
        assert "existing.com" in existing

    def test_llm_rejection_recorded(self):
        verdicts = [{"url": "https://news-site.com", "recommended": False,
                     "name": "News Site", "reliability": "medium",
                     "tags": [], "reason": "Journalism, not primary research"}]
        disc = self._make_discovery(llm_verdicts=verdicts)
        approved = disc._evaluate_candidates([
            {"url": "https://news-site.com", "domain": "news-site.com",
             "discovered_via": "curated_list"}
        ])
        assert approved == []
        disc._repo.upsert_source_candidate.assert_called()
        call_kwargs = disc._repo.upsert_source_candidate.call_args
        assert call_kwargs.kwargs["status"] == "rejected"

    def test_llm_approval_returned(self):
        verdicts = [{"url": "https://new-research.io", "recommended": True,
                     "name": "New Research Lab", "reliability": "high",
                     "tags": ["malware", "apt"], "reason": "Original malware research"}]
        disc = self._make_discovery(llm_verdicts=verdicts)
        approved = disc._evaluate_candidates([
            {"url": "https://new-research.io", "domain": "new-research.io",
             "discovered_via": "curated_list"}
        ])
        assert len(approved) == 1
        assert approved[0]["name"] == "New Research Lab"

    def test_citation_candidates_respect_min_sources(self):
        repo = MagicMock()
        # Only domains with 3+ citations should appear
        repo.get_known_candidate_urls.return_value = set()
        repo.get_cited_domains.return_value = [
            ("binarydefense.com", 4),
            ("low-signal-blog.net", 1),  # below threshold — filtered by repo query
        ]
        repo.upsert_source_candidate = MagicMock()
        disc = self._make_discovery(repo=repo)
        candidates = disc._fetch_citation_candidates(existing_domains=set(), known_urls=set())
        domains = [c["domain"] for c in candidates]
        assert "binarydefense.com" in domains

    def test_run_is_non_blocking_on_llm_failure(self):
        """A failure in the LLM evaluation step must not raise — returns 0."""
        disc = self._make_discovery()
        disc._client.messages.create.side_effect = Exception("API down")
        # Patch curated fetch to return one candidate
        disc._fetch_curated_candidates = MagicMock(return_value=[
            {"url": "https://someresearch.io", "domain": "someresearch.io",
             "discovered_via": "curated_list"}
        ])
        result = disc.run()
        assert result == 0  # graceful, did not raise


class TestScraperCollector:
    @resp_mock.activate
    def test_parse_threatfox_json(self):
        payload = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "192.0.2.1:8080",
                    "ioc_type": "ip:port",
                    "malware": "Cobalt Strike",
                    "confidence_level": 90,
                    "first_seen": "2026-03-10 08:00:00",
                }
            ],
        }
        import json
        resp_mock.add(
            resp_mock.GET,
            "https://threatfox.abuse.ch/export/json/recent/",
            body=json.dumps(payload),
            content_type="application/json",
        )
        config = {
            "name": "ThreatFox",
            "url": "https://threatfox.abuse.ch/export/json/recent/",
            "format": "json",
            "reliability": "high",
            "tags": ["iocs"],
        }
        collector = ScraperCollector(config)
        items = collector.collect()
        assert len(items) == 1
        assert "Cobalt Strike" in items[0].title
