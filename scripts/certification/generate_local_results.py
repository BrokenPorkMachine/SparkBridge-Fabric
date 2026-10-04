#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, platform, shutil, subprocess, sys
from common import ROOT, environment, evidence_ref, new_bundle_id, now_ms, platform_check_id, runner_name, source_revision, write_json

TEMPLATE = ROOT / 'config/certification/results-template.json'
out = ROOT / 'certification-results.local.json'
evidence_dir = ROOT / 'certification-evidence'
evidence_dir.mkdir(parents=True, exist_ok=True)
obj = json.loads(TEMPLATE.read_text())
obj['generated_unix_ms'] = now_ms()
obj['bundle_id'] = new_bundle_id()
obj['source_revision'] = source_revision()
obj['provenance'] = {'runner': runner_name(), 'environment': environment(), 'inputs': []}
checks = {c['id']: c for c in obj['checks']}


def run(command: list[str], timeout: int = 900) -> tuple[bool, str, int, int]:
    started = now_ms()
    try:
        proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
        text = proc.stdout + proc.stderr
        return proc.returncode == 0, text, started, now_ms()
    except Exception as exc:
        return False, str(exc), started, now_ms()


def record(check_id: str, ok: bool, command: str, log_name: str, output: str, started: int, finished: int) -> None:
    log_path = evidence_dir / log_name
    log_path.write_text(output)
    check = checks[check_id]
    check['status'] = 'pass' if ok else 'fail'
    check['evidence'] = [command]
    check['evidence_files'] = [evidence_ref(log_path)]
    check['runner'] = runner_name()
    check['command'] = command
    check['started_unix_ms'] = started
    check['finished_unix_ms'] = finished
    check['detail'] = output[-3000:]


audits = [
    'validate_structure.py', 'rust_delimiter_scan.py', 'audit_secure.py', 'audit_inference.py',
    'audit_snapshots.py', 'audit_candidates.py', 'audit_actions.py', 'audit_agent.py',
    'audit_intelligence.py', 'audit_policy.py', 'audit_cache_validation.py',
    'audit_integrations.py', 'audit_certification.py',
]
source_started = now_ms()
source_ok = True
source_parts: list[str] = []
for audit in audits:
    passed, output, _, _ = run([sys.executable, str(ROOT / 'scripts' / audit)], timeout=300)
    source_ok = source_ok and passed
    source_parts.append(f'===== {audit} =====\n{output}\n')

cargo = shutil.which('cargo')
platform_id = platform_check_id()
if not cargo:
    # The audit suite asserts on source text and cannot tell whether the tree compiles.
    # Say so inside the evidence so a source.audit PASS is never read as "builds clean";
    # the per-platform `rust.*` checks stay skipped and therefore block the 1.0 gate.
    source_parts.append(
        '===== rust build =====\n'
        'NOT VERIFIED: cargo was not available on this runner, so this bundle contains no\n'
        'evidence that the workspace compiles, that tests pass, or that clippy is clean.\n'
        'The string-based audit suite above cannot detect compilation failures.\n'
        'The required per-platform rust.* checks remain skipped, which blocks release.\n\n'
    )
elif not platform_id:
    source_parts.append(
        '===== rust build =====\n'
        f'NOT VERIFIED: this host ({platform.system()}/{platform.machine()}) is not one of the four\n'
        'certified platforms, so no rust.* check was recorded for it.\n\n'
    )
record(
    'source.audit', source_ok, 'python source audit suite', 'source-audit.log',
    ''.join(source_parts), source_started, now_ms(),
)

if cargo and platform_id:
    # `cargo fmt` is intentionally not part of this gate: rustfmt would rewrite the dense
    # source style that scripts/audit_*.py asserts against as exact text. See CONTRIBUTING.md.
    commands = [
        [cargo, 'check', '--workspace', '--all-targets'],
        [cargo, 'test', '--workspace'],
        [cargo, 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'],
    ]
    started = now_ms(); parts = []; rust_ok = True
    for command in commands:
        passed, output, _, _ = run(command, timeout=3600)
        rust_ok = rust_ok and passed
        parts.append(f"$ {' '.join(command)}\n{output}\n")
        if not passed:
            break
    record(platform_id, rust_ok, 'check + test + clippy', f'{platform_id}.log', ''.join(parts), started, now_ms())

ok, output, started, finished = run([sys.executable, 'scripts/certification/check_protocol_matrix.py'])
protocol_log = evidence_dir / 'protocol-matrix.log'
protocol_log.write_text(output)
for check_id in ('compat.protocol-1.9', 'compat.protocol-1.10'):
    check = checks[check_id]
    check['status'] = 'pass' if ok else 'fail'
    check['evidence'] = ['scripts/certification/check_protocol_matrix.py']
    check['evidence_files'] = [evidence_ref(protocol_log)]
    check['runner'] = runner_name()
    check['command'] = f'{sys.executable} scripts/certification/check_protocol_matrix.py'
    check['started_unix_ms'] = started
    check['finished_unix_ms'] = finished
    check['detail'] = output[-1000:]

write_json(out, obj)
print(out)
