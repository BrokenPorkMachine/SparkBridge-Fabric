# CAS + Snapshot Protocol

Fabric Protocol: **1.10**. Snapshot manifest format: **1** (`WorkspaceSnapshot.format_version`).

## Node fabric endpoints

```text
POST /api/v1/nodes/{node_id}/cas/missing
PUT  /api/v1/nodes/{node_id}/cas/{sha256_digest}
GET  /api/v1/nodes/{node_id}/cas/{sha256_digest}
POST /api/v1/nodes/{node_id}/snapshots
GET  /api/v1/nodes/{node_id}/snapshots
```

All endpoints require the existing mTLS executor connection and node bearer binding.

## Missing-object negotiation

The executor submits a bounded list of digests. The server returns only digests absent from the DGX CAS. Uploading the same workspace repeatedly therefore transfers only newly changed content.

## Upload encoding

The request body is the object's original bytes or a zstd-compressed representation with:

```text
Content-Encoding: zstd
```

The server decompresses before digest verification and enforces the object-size limit after decompression. CAS identity is always based on the original bytes.

## Snapshot manifest

A manifest contains sorted logical entries with:

```text
path
kind: file | directory | symlink
digest for files
executable bit where supported
symlink target for links
size
```

It also records Git metadata when the workspace is a Git repository:

```text
HEAD
branch
SHA-256 fingerprint of `git ls-files --stage`
dirty flag
```

The manifest itself is stored as a CAS object. The digest registered in SQLite points to the serialized manifest whose `manifest_digest` field is `null`; this avoids a recursive self-hash.

## Registration validation

Before accepting a snapshot, the server verifies:

1. authenticated node ID equals the request node ID;
2. manifest digest syntax is valid;
3. manifest object exists and passes CAS digest verification;
4. manifest JSON is valid;
5. root name and entry count match registration metadata;
6. every referenced file digest exists in CAS.

An incomplete tree is never registered as a valid snapshot.
