#!/usr/bin/env python3
"""Quick validation script for DNS resolver functionality."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rtphelper.dns_resolver import resolve_host, get_cache_stats, clear_cache

def test_ip_passthrough():
    """Test that IPs pass through unchanged."""
    ip = "10.0.10.11"
    result = resolve_host(ip)
    assert result == ip, f"Expected {ip}, got {result}"
    print(f"✅ IP passthrough: {ip} -> {result}")

def test_localhost():
    """Test localhost resolution."""
    result = resolve_host("localhost")
    assert result in ("127.0.0.1", "::1"), f"Unexpected localhost resolution: {result}"
    print(f"✅ Localhost resolution: localhost -> {result}")

def test_cache():
    """Test cache functionality."""
    clear_cache()
    stats_before = get_cache_stats()
    print(f"✅ Cache cleared: {stats_before['size']} entries")
    
    # Resolve localhost to populate cache
    resolve_host("localhost")
    stats_after = get_cache_stats()
    print(f"✅ Cache populated: {stats_after['size']} entry")
    print(f"   Cache entries: {list(stats_after['entries'].keys())}")

def test_dns_errors():
    """Test DNS error handling."""
    try:
        resolve_host("this-hostname-absolutely-does-not-exist-12345.invalid")
        print("❌ Should have raised ValueError for invalid hostname")
        sys.exit(1)
    except ValueError as e:
        print(f"✅ DNS error handling: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("DNS Resolver Validation Tests")
    print("=" * 60)
    
    try:
        test_ip_passthrough()
        test_localhost()
        test_cache()
        test_dns_errors()
        
        print("\n" + "=" * 60)
        print("✅ All validation tests passed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
