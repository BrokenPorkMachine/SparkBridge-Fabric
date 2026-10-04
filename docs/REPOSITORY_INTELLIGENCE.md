# Repository Intelligence — v0.8

## Purpose

Repository Intelligence supplies the deterministic agent with targeted evidence without dumping an entire repository into model context. Every index is bound to one immutable workspace snapshot.

## Data model

A `RepositoryIndex` records:

- snapshot ID and manifest digest;
- indexed files and detected language;
- symbol definitions;
- identifier references;
- parser/source used for each result;
- build timestamp;
- explicit truncation state.

The serialized index is stored in CAS. SQLite stores the small `RepositoryIndexRecord` used for lookup and provenance.

## Portable indexing

Tree-sitter is used for Rust, Python, C, C++, JavaScript, TypeScript and TSX. A conservative structural fallback handles supported text languages without a compatible grammar in the v0.8 MSRV baseline, including Swift.

Indexing is bounded by server configuration. Files larger than the configured intelligence limit are not parsed into the index.

## Query surfaces

```bash
sparkbridge intelligence list
sparkbridge intelligence build <snapshot-id>
sparkbridge intelligence search <snapshot-id> <query> --limit 50
sparkbridge intelligence symbols <snapshot-id> <query> --limit 50
sparkbridge intelligence references <snapshot-id> <symbol> --limit 100
sparkbridge intelligence history <snapshot-id>
```

`search` reads immutable snapshot bytes from CAS and performs exact case-insensitive lexical matching. `symbols` ranks definition names. `references` returns identifier occurrences. `history` returns the bounded recent Git history captured by snapshot creation.

## Context compiler

For a task, SparkBridge derives an intelligence query from the objective, acceptance criteria and recent action evidence. It ranks files using symbol/reference relationships and term matches, then appends those paths only after explicit context, candidate-touched files and diagnostic paths.

The resulting `ContextBundle` stores a JSON intelligence evidence block including the index digest, ranked paths, symbol matches, native symbol matches, Git history, language counts and index statistics.

## Native LSP overlay

An executor can run:

```bash
sparkbridge-executor --config config/executor.toml \
  --snapshot /path/to/project \
  --workspace-id project \
  --native-intelligence
```

After the snapshot is registered, the executor may launch configured native language servers over stdio. v0.8 requests `textDocument/documentSymbol` for a bounded number/size of source files.

Default command keys are:

```toml
[intelligence_lsp_commands]
rust = ["rust-analyzer"]
c_cpp = ["clangd"]
swift = ["sourcekit-lsp"]
csharp = ["Microsoft.CodeAnalysis.LanguageServer"]
```

Commands are configurable; an unavailable server is skipped. The native report is uploaded over the existing mTLS fabric. The DGX accepts it only if the authenticated node owns the snapshot and every reported symbol path exists as a file in that immutable snapshot.

Native symbols are supplementary evidence. v0.8 does not claim native reference/rename/hover fidelity through this overlay yet.

## Git history

Snapshot creation collects up to 32 recent commits using a read-only `git log`. The snapshot records commit ID, author, Unix authored timestamp and subject. No `git write-tree`, checkout, stash, commit or other mutating Git command is used for repository-intelligence capture.

## Limits and degradation

The server exposes explicit budgets for maximum indexed file bytes, files, symbols, references, result counts and ranked paths. If the repository exceeds an index budget, the index is marked `truncated` and remains usable. SparkBridge never represents a truncated index as complete.

## Correctness rule

Never query repository intelligence without an explicit snapshot ID. There is intentionally no mutable global "current project index". This prevents code, diagnostics and symbols from different workspace generations being mixed in one agent decision.
