import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_development_allows_placeholder_secrets():
    settings = Settings(
        ENVIRONMENT="development",
        SECRET_KEY="CHANGE_ME_IN_ENVIRONMENT",
        ADMIN_PASSWORD="CHANGE_ME_IN_ENVIRONMENT",
    )
    assert settings.DEBUG is False


def test_production_rejects_placeholder_secret_key():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="CHANGE_ME_IN_ENVIRONMENT",
            ADMIN_PASSWORD="a-strong-password",
        )


def test_production_rejects_short_secret_key():
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="too-short",
            ADMIN_PASSWORD="a-strong-password",
        )


def test_production_requires_admin_password():
    with pytest.raises(ValidationError, match="ADMIN_PASSWORD"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a" * 32,
            ADMIN_PASSWORD="CHANGE_ME_IN_ENVIRONMENT",
        )
