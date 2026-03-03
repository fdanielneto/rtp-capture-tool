"""Tests for DNS resolver module."""

from __future__ import annotations

import socket
import time
from unittest.mock import patch

import pytest

from rtphelper.dns_resolver import (
    _is_ip_address,
    clear_cache,
    get_cache_stats,
    resolve_host,
)


class TestIPDetection:
    """Test IP address detection."""

    def test_ipv4_address(self) -> None:
        assert _is_ip_address("10.0.10.11")
        assert _is_ip_address("192.168.1.1")
        assert _is_ip_address("127.0.0.1")
        assert _is_ip_address("255.255.255.255")

    def test_ipv6_address(self) -> None:
        assert _is_ip_address("2001:db8::1")
        assert _is_ip_address("::1")
        assert _is_ip_address("fe80::1")

    def test_not_ip_address(self) -> None:
        assert not _is_ip_address("rtp-node-1.example.com")
        assert not _is_ip_address("localhost")
        assert not _is_ip_address("example.com")
        assert not _is_ip_address("node-1")
        assert not _is_ip_address("")


class TestResolveHost:
    """Test hostname resolution."""

    def test_ip_address_passthrough(self) -> None:
        """IP addresses should be returned unchanged."""
        assert resolve_host("10.0.10.11") == "10.0.10.11"
        assert resolve_host("192.168.1.1") == "192.168.1.1"
        assert resolve_host("  10.0.10.11  ") == "10.0.10.11"

    def test_localhost_resolution(self) -> None:
        """Localhost should resolve to 127.0.0.1 or ::1."""
        ip = resolve_host("localhost")
        assert ip in ("127.0.0.1", "::1")

    @patch("socket.getaddrinfo")
    def test_dns_resolution(self, mock_getaddrinfo) -> None:
        """Test DNS resolution for hostname."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 0))
        ]
        
        clear_cache()
        ip = resolve_host("rtp-node-1.example.com")
        
        assert ip == "10.20.30.40"
        mock_getaddrinfo.assert_called_once()

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo) -> None:
        """Test DNS resolution failure handling."""
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        
        clear_cache()
        with pytest.raises(ValueError, match="Failed to resolve hostname"):
            resolve_host("nonexistent.invalid")

    @patch("socket.getaddrinfo")
    def test_dns_caching(self, mock_getaddrinfo) -> None:
        """Test that DNS results are cached."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 0))
        ]
        
        clear_cache()
        hostname = "rtp-node-cache-test.example.com"
        
        # First call should hit DNS
        ip1 = resolve_host(hostname)
        assert ip1 == "10.20.30.40"
        assert mock_getaddrinfo.call_count == 1
        
        # Second call should use cache
        ip2 = resolve_host(hostname)
        assert ip2 == "10.20.30.40"
        assert mock_getaddrinfo.call_count == 1  # No additional call

    @patch("socket.getaddrinfo")
    def test_cache_bypass(self, mock_getaddrinfo) -> None:
        """Test cache bypass with use_cache=False."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 0))
        ]
        
        clear_cache()
        hostname = "rtp-node-nocache.example.com"
        
        # First call
        resolve_host(hostname, use_cache=True)
        assert mock_getaddrinfo.call_count == 1
        
        # Second call with use_cache=False should hit DNS again
        resolve_host(hostname, use_cache=False)
        assert mock_getaddrinfo.call_count == 2


class TestCacheManagement:
    """Test DNS cache management."""

    def test_clear_cache(self) -> None:
        """Test cache clearing."""
        clear_cache()
        resolve_host("127.0.0.1")  # This won't populate cache (IP passthrough)
        
        stats_before = get_cache_stats()
        assert stats_before["size"] == 0
        
        # Resolve a hostname to populate cache
        resolve_host("localhost")
        stats_after = get_cache_stats()
        assert stats_after["size"] == 1
        
        # Clear and verify
        clear_cache()
        stats_cleared = get_cache_stats()
        assert stats_cleared["size"] == 0

    def test_cache_stats(self) -> None:
        """Test cache statistics."""
        clear_cache()
        resolve_host("localhost")
        
        stats = get_cache_stats()
        assert "size" in stats
        assert "ttl_seconds" in stats
        assert "timeout_seconds" in stats
        assert "entries" in stats
        assert stats["size"] == 1
        assert "localhost" in stats["entries"]
        assert "ip" in stats["entries"]["localhost"]
        assert "age_seconds" in stats["entries"]["localhost"]

    @patch("socket.getaddrinfo")
    @patch("rtphelper.dns_resolver._CACHE_TTL", 0.5)
    def test_cache_expiration(self, mock_getaddrinfo) -> None:
        """Test that cache entries expire after TTL."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 0))
        ]
        
        clear_cache()
        hostname = "rtp-node-ttl.example.com"
        
        # First call
        resolve_host(hostname)
        assert mock_getaddrinfo.call_count == 1
        
        # Wait for cache to expire
        time.sleep(0.6)
        
        # Should hit DNS again after expiration
        resolve_host(hostname)
        assert mock_getaddrinfo.call_count == 2


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_whitespace_handling(self) -> None:
        """Test that whitespace is properly handled."""
        assert resolve_host("  10.0.10.11  ") == "10.0.10.11"
        assert resolve_host("\t192.168.1.1\n") == "192.168.1.1"

    @patch("socket.getaddrinfo")
    def test_ipv6_resolution(self, mock_getaddrinfo) -> None:
        """Test IPv6 DNS resolution."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::42", 0, 0, 0))
        ]
        
        clear_cache()
        ip = resolve_host("ipv6.example.com")
        assert ip == "2001:db8::42"

    @patch("socket.getaddrinfo")
    def test_timeout_handling(self, mock_getaddrinfo) -> None:
        """Test DNS timeout handling."""
        mock_getaddrinfo.side_effect = socket.timeout("DNS query timed out")
        
        clear_cache()
        with pytest.raises(ValueError, match="Failed to resolve hostname"):
            resolve_host("slow-dns.example.com")
