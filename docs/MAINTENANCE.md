# Maintenance, Backup and Updates — v0.12.0-rc3

## Backup

For a strict point-in-time recovery set, stop the server first:

```bash
sudo systemctl stop sparkbridge-server
sudo sparkbridge backup create \
  --root / \
  --output /srv/backups/sparkbridge-$(date +%F) \
  --include etc/sparkbridge \
  --include var/lib/sparkbridge
sudo sparkbridge backup verify --backup /srv/backups/sparkbridge-$(date +%F)
sudo systemctl start sparkbridge-server
```

The backup manifest stores SHA-256, size, and (on Unix) the original file mode for every copied regular file. Restore reapplies recorded Unix modes, which matters for CA/private-key material. Symlinks are refused rather than followed.

A full backup includes the CA private key and node/security database. Protect the destination at least as strongly as `/etc/sparkbridge/pki`.

## Restore

Restore to a clean host/root when possible:

```bash
sudo sparkbridge backup verify --backup /srv/backups/sparkbridge-2026-10-04
sudo sparkbridge backup restore \
  --backup /srv/backups/sparkbridge-2026-10-04 \
  --target /
```

Existing files cause restore to stop unless `--overwrite` is explicitly supplied.

## Signed staged updates

Create an artifact manifest:

```bash
python3 scripts/make_update_manifest.py \
  SparkBridge-Fabric-v0.12.0-rc3.zip \
  --version 0.12.0
```

Sign the exact `update-manifest.json` bytes using your controlled Ed25519 release key. Store the raw/hex/base64 public key separately on target systems.

Verify:

```bash
sparkbridge update verify \
  --manifest update-manifest.json \
  --signature update-manifest.sig \
  --public-key release-public-key \
  --artifact SparkBridge-Fabric-v0.12.0-rc3.zip
```

Stage only after verification:

```bash
sparkbridge update stage \
  --manifest update-manifest.json \
  --signature update-manifest.sig \
  --public-key release-public-key \
  --artifact SparkBridge-Fabric-v0.12.0-rc3.zip \
  --staging-dir /var/lib/sparkbridge/update-staging
```

SparkBridge intentionally does not replace the live binary automatically in v0.11. Use your service manager/change-control process after staging.

## CAS garbage collection

Dry-run while the server is stopped if possible:

```bash
python3 scripts/cas_gc.py \
  --database /var/lib/sparkbridge/sparkbridge.db \
  --cas /var/lib/sparkbridge/cas \
  --min-age-seconds 86400
```

Delete only after reviewing counts:

```bash
sudo systemctl stop sparkbridge-server
python3 scripts/cas_gc.py \
  --database /var/lib/sparkbridge/sparkbridge.db \
  --cas /var/lib/sparkbridge/cas \
  --min-age-seconds 604800 \
  --delete \
  --confirm-server-stopped
sudo systemctl start sparkbridge-server
```

Reachability roots include durable snapshot/candidate/index/native-intelligence/cache/action/task/promotion state. JSON CAS objects are recursively inspected for referenced digests. The age grace period protects recent orphan objects from immediate deletion.

`--delete` requires `--confirm-server-stopped` and a `--min-age-seconds` greater than zero; both are refused rather than defaulted, because deleting live state is not recoverable. The database is opened read-only, so GC cannot write to a live server's state.

GC is fail-closed. If a reachability table cannot be read, a record cannot be parsed, or a live object is larger than `--max-traversable-bytes` (default 128 MiB, which must be at least your `cas_max_object_bytes`), the run aborts with a non-zero exit instead of treating the unknown objects as garbage. A large live manifest that cannot be traversed would otherwise make its own children look unreachable.

## rc3 certification note

`scripts/certification/backup_restore_drill.sh` is a local preflight that now proves digest verification, restored-content equality, Unix permission preservation where supported, and rejection of a deliberately corrupted backup. The 1.0 gate still requires a production-style isolated-host restore.

`scripts/certification/update_rollback_drill.sh` proves staging does not mutate the selected live binary. It is **not** a substitute for the required production signed-update and service-manager rollback drill; record that external drill with `scripts/certification/record_check.py`.
