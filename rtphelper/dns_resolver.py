"""DNS resolution with caching for dynamic RTP host addresses.

Provides hostname-to-IP resolution with TTL-based caching to minimize DNS queries
while supporting dynamic IP updates for RTP capture hosts.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import time
from typing import Dict, Tuple

LOGGER = logging.getLogger(__name__)

# IP address pattern (IPv4 and basic IPv6)
_IP_PATTERN = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}|"  # IPv4
    r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6
    r")$"
)

# DNS resolution cache: hostname -> (ip, timestamp)
_DNS_CACHE: Dict[str, Tuple[str, float]] = {}

# Cache TTL in seconds (default 60s, configurable via environment)
_DEFAULT_CACHE_TTL = 60.0
_CACHE_TTL = float(os.environ.get("RTPHELPER_DNS_CACHE_TTL", str(_DEFAULT_CACHE_TTL)))

# DNS resolution timeout in seconds
_DEFAULT_DNS_TIMEOUT = 5.0
_DNS_TIMEOUT = float(os.environ.get("RTPHELPER_DNS_TIMEOUT", str(_DEFAULT_DNS_TIMEOUT)))


def _is_ip_address(address: str) -> bool:
    """Check if the address is already an IP address (IPv4 or IPv6)."""
    return bool(_IP_PATTERN.match(address))


def _resolve_dns(hostname: str) -> str:
    """Perform DNS resolution with timeout.
    
    Args:
        hostname: Hostname or FQDN to resolve
        
    Returns:
        Resolved IP address
        
    Raises:
        socket.gaierror: DNS resolution failed
        socket.timeout: DNS resolution timed out
    """
    LOGGER.debug(
        "DNS resolution hostname=%s timeout=%ss",
        hostname,
        _DNS_TIMEOUT,
        extra={"category": "CAPTURE"},
    )
    
    # Set default timeout for DNS operations
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        # We want the first result's sockaddr[0] which is the IP address
        result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not result:
            raise socket.gaierror(f"No address found for hostname: {hostname}")
        
        ip = result[0][4][0]
        LOGGER.info(
            "DNS resolution successful hostname=%s ip=%s",
            hostname,
            ip,
            extra={"category": "CAPTURE"},
        )
        return ip
    finally:
        socket.setdefaulttimeout(old_timeout)


def resolve_host(address: str, use_cache: bool = True) -> str:
    """Resolve a hostname or IP address to an IP address.
    
    If the address is already an IP, returns it unchanged.
    If it's a hostname, performs DNS resolution with caching.
    
    Args:
        address: IP address, hostname, or FQDN
        use_cache: Whether to use cached DNS results (default True)
        
    Returns:
        IP address (either the input if already IP, or resolved from DNS)
        
    Raises:
        ValueError: DNS resolution failed
    """
    address = address.strip()
    
    # Fast path: already an IP address
    if _is_ip_address(address):
        return address
    
    # Check cache if enabled
    now = time.time()
    if use_cache and address in _DNS_CACHE:
        cached_ip, cached_at = _DNS_CACHE[address]
        age = now - cached_at
        if age < _CACHE_TTL:
            LOGGER.debug(
                "DNS cache hit hostname=%s ip=%s age=%0.1fs",
                address,
                cached_ip,
                age,
                extra={"category": "CAPTURE"},
            )
            return cached_ip
        else:
            LOGGER.debug(
                "DNS cache expired hostname=%s age=%0.1fs ttl=%ss",
                address,
                age,
                _CACHE_TTL,
                extra={"category": "CAPTURE"},
            )
    
    # Perform DNS resolution
    try:
        ip = _resolve_dns(address)
        _DNS_CACHE[address] = (ip, now)
        return ip
    except (socket.gaierror, socket.timeout) as exc:
        LOGGER.error(
            "DNS resolution failed hostname=%s error=%s",
            address,
            exc,
            extra={"category": "ERRORS"},
        )
        raise ValueError(f"Failed to resolve hostname '{address}': {exc}") from exc
    except Exception as exc:
        LOGGER.error(
            "Unexpected DNS resolution error hostname=%s error=%s",
            address,
            exc,
            extra={"category": "ERRORS"},
        )
        raise ValueError(f"DNS resolution error for '{address}': {exc}") from exc


def clear_cache() -> None:
    """Clear the DNS resolution cache.
    
    Useful for testing or forcing fresh DNS lookups.
    """
    _DNS_CACHE.clear()
    LOGGER.debug("DNS cache cleared", extra={"category": "CAPTURE"})


def get_cache_stats() -> Dict[str, any]:
    """Get DNS cache statistics for observability.
    
    Returns:
        Dictionary with cache size and entries
    """
    return {
        "size": len(_DNS_CACHE),
        "ttl_seconds": _CACHE_TTL,
        "timeout_seconds": _DNS_TIMEOUT,
        "entries": {
            hostname: {"ip": ip, "age_seconds": time.time() - cached_at}
            for hostname, (ip, cached_at) in _DNS_CACHE.items()
        },
    }
