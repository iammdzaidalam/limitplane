# Benchmarks

Apple M5, Go 1.26. Reproduce: `make bench`.

| Benchmark | ns/op | allocs/op |
|---|---:|---:|
| GCRA check, one key | 41 | 0 |
| GCRA check, 512 keys | 42 | 0 |
| GCRA check, 512 keys, parallel | 29 | 0 |
| Gateway middleware (no-op limiter) | 254 | 6 |
| Hub `OnDecision` (request-path cost of stats/SSE) | 53 | 0 |

The middleware figure is dominated by `net/http` header handling, not the limiter.
Redis-backed checks are bounded by one network round trip, so measure them on your own network.
