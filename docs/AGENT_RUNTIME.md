# Deterministic Agent Runtime — v0.7

## Purpose

v0.7 connects the inference, immutable-candidate, and remote-action layers into a durable coding loop without giving the model direct authority over the filesystem or command execution.

## Core rule

```text
model = proposes
SparkBridge = remembers + validates + schedules
executor = runs native tools
candidate = immutable proposed change
user = promotion authority
```

## TaskSpec

A task starts from a persisted `TaskSpec` containing:

- objective;
- logical workspace ID;
- immutable base snapshot ID;
- model name;
- explicit initial context paths;
- acceptance criteria;
- ordered validation actions;
- wall/model/action/candidate/repair budgets;
- candidate/validation completion requirements.

Task specs are deliberately reviewable JSON rather than implicit chat state.

## Durable state machine

Primary states:

```text
CREATED
  ↓
RUNNING
  ├──► WAITING_FOR_ACTION ───► RUNNING
  ├──► PAUSED ───────────────► RUNNING
  ├──► COMPLETED
  ├──► FAILED
  ├──► CANCELLED
  └──► BUDGET_EXCEEDED
```

The server serializes transitions for each task with a per-task runtime lock. Different tasks may advance independently.

## Event journal

Every transition is appended to `task_events` with:

- globally unique event ID;
- task ID;
- monotonic task sequence;
- event kind;
- timestamp;
- event-specific data;
- resulting task projection.

The `tasks` table is the fast materialized projection. The latest event also contains enough state to reconstruct the projection for audit/recovery verification.

## ContextBundle

Before each model turn SparkBridge builds and stores a content-addressed context bundle.

It contains:

- objective;
- acceptance criteria;
- base snapshot identity;
- current candidate identity;
- bounded source-file content;
- current candidate overlay summary;
- last build/test evidence;
- current task counters.

Initial source context comes from `context_paths`.

After a failed validation action, normalized diagnostic paths are automatically added to the next context turn. This is a deliberate bridge until the v0.8 repository-intelligence layer supplies symbol/reference retrieval.

## Model contract

The model may return exactly one structured JSON directive:

```text
candidate
run_validation
complete
pause
fail
```

The model cannot submit shell commands. Validation commands come from the operator-authored TaskSpec.

### Candidate directive

A candidate directive describes the complete desired delta against the immutable base snapshot.

Supported text-oriented operations:

```text
create_file
modify_file
delete_file
rename_file
set_executable
```

Create/modify operations contain complete UTF-8 file content. SparkBridge translates them into CAS-backed candidate operations and applies the same deterministic candidate validation used by manual candidate creation.

Invalid model candidates are not accepted. The rejection reason becomes evidence for a repair turn.

## Candidate validation sandbox

Agent validation never runs in the developer's live checkout.

An action carrying `candidate_id` causes the executor to:

1. authenticate the candidate/node/workspace relationship;
2. fetch the candidate and base manifest from DGX CAS;
3. fetch missing file objects into executor-local CAS;
4. create a disposable sandbox under `action_sandbox_path`;
5. materialize the immutable base tree;
6. apply the candidate delta;
7. execute the allowlisted validation action;
8. normalize diagnostics to workspace-relative paths;
9. report the action result durably;
10. delete the sandbox.

Stale sandbox directories are cleaned on executor startup.

### Symlink behavior

Unix sandboxes reconstruct only relative symlinks that cannot escape the sandbox root.

Absolute or escaping symlinks are rejected.

Windows candidate sandboxes containing symlink entries are rejected in v0.7 rather than requiring developer-mode/admin symlink privileges or silently changing semantics.

## Validation pipeline

TaskSpec validation actions are ordered.

Example:

```text
candidate
   ↓
cargo check
   ↓ pass
cargo test --workspace
   ↓ pass
model review / complete
```

A failure resets validation progress and increments the repair-cycle counter. The next model turn receives normalized diagnostics and bounded stdout/stderr evidence.

Each validation action is classified `pure` because it operates on a disposable candidate sandbox. It still obeys the executor command allowlist, timeout/output limits, capability scheduler, action leases, and cancellation rules.

## Completion

If `require_candidate=true`, the model cannot complete without a candidate.

If `require_validation=true` and validation actions exist, every configured validation action must pass for the current candidate before completion is accepted.

Completion does not promote the candidate.

Promotion remains the separate v0.5 transactional workflow so the user can inspect the candidate and evidence before live mutation.

## Budgets

Each task has hard limits for:

```text
wall time
model calls
actions
candidates
repair cycles
```

Crossing a budget moves the task to `budget_exceeded`; the model cannot extend its own budget.

## Pause / resume / cancel

Pause stops new model/action transitions while preserving all state.

Resume returns a paused task to the runnable state.

Cancel marks the task terminal and requests cancellation of a currently pending action.

## Restart recovery

On server startup:

- a running task with a known pending action is returned to `waiting_for_action`;
- if an agent-owned action was durably created immediately before a crash but the task projection was not yet updated, its `origin_task_id` lets recovery reattach it;
- existing action/outbox semantics continue to handle executor/server disconnects.

A model call itself is not assumed deterministic. SparkBridge records `ModelRequested` before inference; if the server dies during inference, the consumed model-call budget remains consumed and the next run may request a fresh model turn.

## Operator CLI

```bash
sparkbridge tasks create --spec task.json
sparkbridge tasks list
sparkbridge tasks show <task-id>
sparkbridge tasks events <task-id>
sparkbridge tasks run <task-id> --follow
sparkbridge tasks pause <task-id>
sparkbridge tasks resume <task-id>
sparkbridge tasks cancel <task-id>
```

## v0.7 boundaries

Not implemented yet:

- repository-wide symbol/reference intelligence;
- automatic context discovery before the first model turn;
- AST/semantic merge generation;
- secret broker / context secret redaction;
- privileged actions;
- automatic promotion;
- Git commit/push/deployment;
- WSL/container/simulator domains;
- portable network sandbox enforcement;
- multiple simultaneous leased actions per executor.
