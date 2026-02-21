from rtphelper.services.capture_service import (
    DEFAULT_ROLLING_PCAP_MAX_SECONDS,
    _rolling_pcap_max_seconds,
)


def test_rolling_pcap_max_seconds_accepts_zero(monkeypatch) -> None:
    monkeypatch.setenv("RTPHELPER_ROLLING_PCAP_MAX_SECONDS", "0")
    assert _rolling_pcap_max_seconds() == 0


def test_rolling_pcap_max_seconds_falls_back_on_negative(monkeypatch) -> None:
    monkeypatch.setenv("RTPHELPER_ROLLING_PCAP_MAX_SECONDS", "-1")
    assert _rolling_pcap_max_seconds() == DEFAULT_ROLLING_PCAP_MAX_SECONDS


def test_rolling_pcap_max_seconds_falls_back_on_invalid(monkeypatch) -> None:
    monkeypatch.setenv("RTPHELPER_ROLLING_PCAP_MAX_SECONDS", "abc")
    assert _rolling_pcap_max_seconds() == DEFAULT_ROLLING_PCAP_MAX_SECONDS
