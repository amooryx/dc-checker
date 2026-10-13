<div align="center">
  <img src="./banner.svg" alt="dc-checker" width="800">
</div>

# dc-checker

> Red team security tool — authorized use only.

```bash
python dc_checker.py --help
```

> **Authorized security testing only.**

DNS discovery validates DNS response headers, the queried SRV question, and
compressed SRV records before accepting same-domain targets. Malformed or
inconclusive DNS responses are reported to stderr. Its resolver is currently
hard-coded to `8.8.8.8`, so internal DNS zones may not be discoverable.

This tool performs TCP port-reachability checks and heuristic DC identification;
open ports do not establish that a host is a domain controller or that
replication is healthy. NBT discovery is a local-subnet broadcast and may not
work across routed networks. It does not authenticate or change domain state.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
