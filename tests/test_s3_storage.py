import os

import pytest

from rtphelper.services.s3_storage import _parse_size_bytes_env


def test_parse_size_bytes_env_accepts_plain_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_SIZE", "8388608")
    assert _parse_size_bytes_env("TEST_SIZE", 1) == 8_388_608


def test_parse_size_bytes_env_accepts_decimal_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_SIZE", "200MB")
    assert _parse_size_bytes_env("TEST_SIZE", 1) == 200_000_000


def test_parse_size_bytes_env_accepts_binary_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_SIZE", "100MiB")
    assert _parse_size_bytes_env("TEST_SIZE", 1) == 104_857_600


def test_parse_size_bytes_env_uses_default_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_SIZE", raising=False)
    assert _parse_size_bytes_env("TEST_SIZE", 1234) == 1234


def test_parse_size_bytes_env_rejects_invalid_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_SIZE", "abc")
    with pytest.raises(ValueError):
        _parse_size_bytes_env("TEST_SIZE", 1)

