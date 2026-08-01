"""Shared pytest fixtures for the OpenID integration."""

import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Allow tests to load custom integrations."""
    yield
