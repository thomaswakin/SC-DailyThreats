"""Shared pytest fixtures."""

import pytest
from pathlib import Path
from threats.storage import Database, Repository


@pytest.fixture
def db():
    """In-memory SQLite database for tests."""
    database = Database(":memory:")
    database.connect()
    yield database
    database.close()


@pytest.fixture
def repo(db):
    return Repository(db)


@pytest.fixture
def sample_rss_xml():
    return (Path(__file__).parent / "fixtures" / "sample_feed.xml").read_text()


@pytest.fixture
def sample_llm_response():
    import json
    return json.loads(
        (Path(__file__).parent / "fixtures" / "sample_llm_response.json").read_text()
    )
