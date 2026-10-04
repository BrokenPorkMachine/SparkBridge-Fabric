#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text()

checks: list[tuple[str, bool]] = []

def check(name: str, condition: bool) -> None:
    checks.append((name, condition))

cargo = text("Cargo.toml")
server = text("apps/sparkbridge-server/src/main.rs")
store = text("apps/sparkbridge-server/src/store.rs")
pki = text("apps/sparkbridge-server/src/pki.rs")
executor = text("apps/sparkbridge-executor/src/main.rs")
identity = text("apps/sparkbridge-executor/src/identity.rs")
protocol = text("crates/sparkbridge-protocol/src/lib.rs")
config = text("crates/sparkbridge-config/src/lib.rs")

check("workspace version is 0.12.0", 'version = "0.12.0"' in cargo)
check("protocol minor advanced to 1.10", "PROTOCOL_MINOR: u16 = 10" in protocol)
check("admin bind defaults to loopback", 'admin_bind: "127.0.0.1:7787"' in config)
check("server rejects remote admin", "admin_addr.ip().is_loopback()" in server)
check("fabric uses WebPkiClientVerifier", "WebPkiClientVerifier" in server)
check("fabric uses client certificate verifier", ".with_client_cert_verifier(verifier)" in server)
check("enrollment token is hashed", "hash_secret(raw_token)" in store)
check("one-time token is transactionally consumed", "consumed_unix_ms" in store and "transaction.commit()" in store)
check("executor generates local key", "KeyPair::generate()" in identity)
check("executor sends CSR", "serialize_request(&key)" in identity)
check("server overwrites CSR policy", "csr.params = params" in pki)
check("client cert restricted to ClientAuth", "ExtendedKeyUsagePurpose::ClientAuth" in pki)
check("executor uses mTLS identity", ".identity(identity)" in executor)
check("executor pins CA", ".add_root_certificate(ca)" in executor)
check("node request has bearer binding", ".bearer_auth(&loaded.metadata.node_secret)" in executor)
check("revocation is durable", "revoked_unix_ms" in store)
check("rotation creates credential grace", "previous_secret_expires_unix_ms" in store)
check("identity activation is generation based", 'join("credentials")' in identity and 'current.json' in identity)
check("reconnect is exponential", "saturating_mul(2).min(max_backoff)" in executor)
check("feature negotiation implemented", "negotiate_features" in protocol and "accepted_features" in protocol)
check("body limit exists", "DefaultBodyLimit::max" in server)
check("public trust roots are disabled", executor.count(".tls_built_in_root_certs(false)") >= 2)
check("executor validates configuration", 'config.validate().context("validating executor configuration")?' in executor)
check("server validates configuration", 'config.validate().context("validating server configuration")?' in server)
check("fatal auth failures stop reconnecting", "FabricConnectionError::Fatal" in executor and "return Err(error)" in executor)
check("identity pointer is private", 'write_private(&temp_current, &encoded)' in identity)
check("old identity generations are pruned", "prune_old_generations" in identity)
check("SQLite schema is explicitly versioned", "PRAGMA user_version = 9" in store and "SCHEMA_VERSION: u32 = 9" in store)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(("PASS" if ok else "FAIL") + ": " + name)

if failed:
    print(f"\n{len(failed)} secure-fabric invariant(s) failed", file=sys.stderr)
    sys.exit(1)

print(f"\nSecure Fabric audit passed: {len(checks)} invariants")
