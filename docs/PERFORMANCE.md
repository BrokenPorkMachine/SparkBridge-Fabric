# SparkBridge Performance & Load Characterization — v0.12

## Measure task completion, not only tokens/second

Primary metrics:

- successful engineering tasks / wall-clock time;
- time to first useful model/action event;
- model queue delay;
- model load time;
- prompt evaluation rate;
- decode rate;
- gateway time-to-first-chunk;
- action queue/lease time;
- build/test time;
- CAS bytes sent vs reused;
- cache hit rate;
- model/tool/candidate attempts per task.

## Candidate certification metrics

The profile accepts optional local thresholds for:

- `gateway_local_overhead_p95_ms` (target ≤25 ms on DGX-local gateway path);
- `control_health_p95_ms` (target ≤100 ms locally).

These are not WAN latency promises. Remote RTT is physics and must be recorded separately.

## Required benchmark methodology

1. pin release/config/model identity;
2. warm model once, then separate cold/warm measurements;
3. use the same prompt/context snapshot;
4. record at least 30 samples for latency percentiles;
5. report median and p95, not only fastest run;
6. record DGX power/thermal state and concurrent work;
7. compare local Ollama timings to SparkBridge timings to isolate gateway overhead;
8. record cache and prompt-cache status.

## Agent benchmark

Use representative compile-fix-test tasks and report:

- completion success;
- total wall time;
- number of model calls;
- number of tool calls;
- candidate count;
- compile/test retries;
- total generated tokens;
- validation result across required platforms.

A slower token generator that completes correctly in fewer repair loops may be the superior coding model.
