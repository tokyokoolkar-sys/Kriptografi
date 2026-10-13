"""Shared fixtures for the test suite."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kriptografi.api.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    """An HTTP client bound to the ASGI app, no server process needed."""
    return TestClient(app)


@pytest.fixture(scope="session")
def alphabet_str() -> str:
    from kriptografi.alphabet import ALPHABET

    return ALPHABET
