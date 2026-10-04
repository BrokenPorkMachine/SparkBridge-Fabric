# Candidate Workspaces and Transactional Promotion

## Purpose

v0.5 establishes the only sanctioned path from DGX-generated source changes to a developer's live macOS, Windows or Linux workspace.

The important separation is:

```text
DGX:      creates immutable candidate intent
Executor: owns live filesystem authority
```

## Candidate operation semantics

### `create_file`

Requires the destination to be absent from the base snapshot. During promotion it must also still be absent from the live tree unless it already contains exactly the candidate content.

### `modify_file`

Carries:

```text
path
expected base digest
replacement content digest
size
executable state
```

If live content still equals the base digest, replacement is direct. If live content differs, v0.5 attempts conservative text three-way merge.

### `delete_file`

Deletes only if current content still equals the expected base digest. A user-modified file is never silently deleted.

### `rename_file`

Renames only if the source still contains the expected base content and the destination remains absent. v0.5 does not combine rename+content-edit in a single operation; represent complex transformations as a later candidate design extension.

### `set_executable`

Changes executable mode only if content still equals the expected base digest. On non-Unix systems this is a semantic no-op at the filesystem layer.

## Candidate validation

The server validates candidate operations against the immutable base snapshot and rejects:

- missing modify/delete/rename sources;
- non-regular-file sources;
- base digest mismatches;
- create/rename destinations already present in base;
- path traversal;
- backslash logical paths;
- Windows reserved names;
- duplicate/case-colliding touched paths;
- referenced CAS objects that fail digest/size verification.

## Merge algorithm

v0.5 is deliberately conservative. It finds the single effective changed range between base/current and base/candidate. Two changed ranges merge automatically only if they are disjoint.

This means some logically mergeable multi-hunk edits may still be reported as conflicts. That is intentional: false conflicts are acceptable; silent source loss is not.

## Transaction journal

Transaction state is stored under:

```text
<workspace>/.sparkbridge/transactions/<uuid>/journal.json
```

The journal transitions:

```text
preparing → applying → committed
                    ↘ rolled_back
```

All touched existing regular files are copied into local CAS before `applying` is persisted.

On a later locked promotion, any journal left in `preparing`/`applying` is rolled back before new mutation occurs.

## Last-moment preconditions

Immediately before a write/delete/rename/mode change, SparkBridge verifies the relevant path still has the digest observed during planning. Create operations verify the path is still absent.

This closes the interval between pre-commit snapshotting and the individual filesystem operation.

## Symlink rule

Candidate logical paths are never permitted to escape the workspace through a live symlink ancestor. Existing non-regular touched objects are rejected.

## Promotion outcome records

Every successful dry-run or completed attempt is written to SQLite with:

```text
candidate ID
workspace ID
node ID
outcome
base manifest
action-start observed manifest
result manifest when applied
generation before/after
merged file count
conflicts/errors
timestamp
```

The server accepts `applied` only when the reported result manifest already exists in DGX CAS.

## Recovery limitation

Rollback protects the set of paths touched by the candidate. It does not undo unrelated edits a human makes elsewhere in the workspace while promotion is active.

That behavior is intentional: unrelated user work remains authoritative.
