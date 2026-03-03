# DNS Resolution for Dynamic RTP Hosts

## Overview
This implementation adds DNS resolution support for RTP capture hosts, allowing hostnames/FQDNs to be used in addition to static IP addresses in `config/hosts.yaml`.

## Features
- ✅ Backward compatible: static IPs continue to work unchanged
- ✅ DNS caching with configurable TTL (default 60s)
- ✅ Automatic resolution at connection time
- ✅ IPv4 and IPv6 support
- ✅ Detailed logging for troubleshooting

## Configuration

### hosts.yaml Example
```yaml
environments:
  PRD:
    regions:
      EU:
        sub-region:
          eu-west-1:
            hosts:
              # Static IP (unchanged behavior)
              - id: prd-eu-west-1-rtp-1
                address: 10.0.10.11
                description: Static IP host
                interfaces: ["ens5"]
              
              # DNS hostname (NEW)
              - id: prd-eu-west-1-rtp-2
                address: rtp-node-2.internal.example.com
                description: Dynamic DNS host
                interfaces: ["ens5"]
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RTPHELPER_DNS_CACHE_TTL` | `60` | DNS cache TTL in seconds |
| `RTPHELPER_DNS_TIMEOUT` | `5.0` | DNS query timeout in seconds |

## How It Works

```
Configuration Load
       ↓
   hosts.yaml
   address: rtp.example.com
       ↓
   RpcapClient.__init__()
       ↓
   resolve_host(address)
       ↓
   ┌─ Is IP? → Return unchanged
   │
   └─ Is hostname? → DNS lookup → Cache → Return IP
       ↓
   socket.connect(resolved_ip, port)
```

## Architecture Changes

### New Files
- `rtphelper/dns_resolver.py` - DNS resolution module with caching
- `tests/test_dns_resolver.py` - Comprehensive unit tests

### Modified Files
- `rtphelper/services/rpcap_client.py` - Call `resolve_host()` in `__init__`
- `config/hosts.yaml.example` - Documentation and examples

### Integration Points
The DNS resolver is invoked at 3 locations:
1. **Preflight checks** (reachability test)
2. **Capture start** (each RpcapClient instantiation)
3. **Reconnection attempts** (after network failures)

## Logging

DNS resolution activity is logged with category `CAPTURE`:

```
INFO - DNS resolution successful hostname=rtp-node-1.internal.example.com ip=10.20.30.40
DEBUG - DNS cache hit hostname=rtp-node-1.internal.example.com ip=10.20.30.40 age=12.3s
DEBUG - Connecting rpcap host=10.20.30.40 (resolved from rtp-node-1.internal.example.com) port=2002
```

Errors are logged with category `ERRORS`:

```
ERROR - DNS resolution failed hostname=invalid.host error=[Errno -2] Name or service not known
```

## Testing

### Unit Tests
```bash
python3 -m pytest tests/test_dns_resolver.py -v
```

### Manual Validation
```bash
python3 scripts/validate_dns_resolver.py
```

### Integration Test
1. Edit `config/hosts.yaml` with a real DNS hostname
2. Start the web UI: `./scripts/run.sh`
3. Check `/api/targets?environment=QA&refresh=true`
4. Start a capture session
5. Verify RPCAP connection in logs

## Cache Management

```python
from rtphelper.dns_resolver import clear_cache, get_cache_stats

# Clear all cached entries
clear_cache()

# Get cache statistics
stats = get_cache_stats()
# {
#   "size": 3,
#   "ttl_seconds": 60.0,
#   "timeout_seconds": 5.0,
#   "entries": {
#     "rtp-node-1.example.com": {
#       "ip": "10.20.30.40",
#       "age_seconds": 45.2
#     }
#   }
# }
```

## Performance Impact

| Operation | Before | After | Impact |
|-----------|--------|-------|--------|
| IP address host | 0ms | 0ms | None (passthrough) |
| DNS host (cached) | N/A | <1ms | Minimal (cache lookup) |
| DNS host (uncached) | N/A | <100ms | First connection only |
| Reconnection | 0ms | 0ms | Uses cache |

## Migration Guide

### From Static IPs to DNS

**Before:**
```yaml
- id: rtp-1
  address: 10.0.10.11
```

**After:**
```yaml
- id: rtp-1
  address: rtp-1.internal.example.com
```

No code changes required. Update `hosts.yaml` and restart the application.

## Troubleshooting

### DNS Resolution Failures

**Symptom:** Host marked unreachable, logs show "DNS resolution failed"

**Solutions:**
1. Verify hostname is valid: `nslookup rtp-node-1.example.com`
2. Check DNS timeout: increase `RTPHELPER_DNS_TIMEOUT` if network is slow
3. Use static IP as fallback during investigation

### Cache Issues

**Symptom:** Host IP changed but old IP still used

**Solutions:**
1. Wait for cache TTL to expire (default 60s)
2. Restart application to clear cache
3. Reduce `RTPHELPER_DNS_CACHE_TTL` for faster updates

### Performance

**Symptom:** Slow connection establishment

**Solutions:**
1. Verify DNS server is fast: `time nslookup hostname`
2. Increase cache TTL to reduce DNS queries
3. Consider using static IPs for performance-critical hosts

## Security Considerations

- DNS responses are not validated (DNSSEC not implemented)
- Cache poisoning risk if DNS infrastructure is compromised
- Use internal/private DNS zones for production hosts
- Consider firewall rules to restrict DNS query destinations
