# Benchmarks

Apple M5, Go 1.26. Reproduce: `make bench`.

| Benchmark | ns/op | allocs/op |
|---|---:|---:|
| GCRA check, one key | 42 | 0 |
| GCRA check, 512 keys | 43 | 0 |
| GCRA check, 512 keys, parallel | 28 | 0 |
| Full local check: ban lookup + monthly cap + GCRA, 512 keys, one CIDR ban | 105 | 0 |
| Ban lookup, exact IP hit (1004 bans) | 8 | 0 |
| Ban lookup, miss with 4 CIDR lengths in use | 40 | 0 |
| Gateway middleware (no-op meter) | 200 | 4 |
| Hub `OnDecision` (request-path cost of stats/SSE) | 53 | 0 |

The middleware figure is dominated by `net/http` header handling, not the limiter.
A Redis-backed check is one network round trip (ban, monthly and burst run in one script), so measure it on your own network.
