# SparkBridge Compatibility Commitment — v0.12 Candidate

## Frozen versions

v0.12 intentionally retains:

- Fabric Protocol **1.10**
- SQLite schema **9**

This is the first explicit pre-1.0 compatibility freeze.

## Wire compatibility

Within protocol major 1, endpoints negotiate the smaller minor revision. The supplied fixture requires:

- 1.8 client ↔ 1.10 server → 1.8
- 1.9 client ↔ 1.10 server → 1.9
- 1.10 client ↔ 1.10 server → 1.10
- 1.99 client ↔ 1.10 server → 1.10
- 2.0 client ↔ 1.10 server → incompatible

Run:

```bash
python3 scripts/certification/check_protocol_matrix.py
```

## Database compatibility

v0.12 introduces no migration beyond schema 9. An upgrade from v0.11 to v0.12 therefore changes binaries and release metadata, not durable database layout.

## 1.0 commitment target

For the 1.x line:

- protocol major 1 remains backward-compatible within documented feature negotiation;
- database migrations are forward-only and explicitly versioned;
- the immediately previous supported release must have a documented rollback/restore path;
- optional features must never be silently treated as mandatory by an older negotiated peer.
