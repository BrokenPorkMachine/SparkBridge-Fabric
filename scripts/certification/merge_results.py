#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, math, pathlib, sys, time, uuid

if len(sys.argv) < 3:
    raise SystemExit('usage: merge_results.py OUTPUT INPUT...')

out = pathlib.Path(sys.argv[1])
inputs = [pathlib.Path(p) for p in sys.argv[2:]]
bundles = [json.loads(path.read_text()) for path in inputs]
identity = {(b['release'], b['protocol'], b['database_schema']) for b in bundles}
if len(identity) != 1:
    raise SystemExit(f'incompatible bundle identities: {sorted(identity)}')
revisions = {b.get('source_revision') for b in bundles}
if None in revisions or '' in revisions:
    raise SystemExit('every input bundle must contain source_revision')
if len(revisions) != 1:
    raise SystemExit(f'mixed source revisions cannot be certified: {sorted(revisions)}')
release, protocol, schema = next(iter(identity))
source_revision = next(iter(revisions))


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merge_list(left, right):
    values=[]
    for item in list(left or []) + list(right or []):
        if item not in values:
            values.append(item)
    return values


def merge_check(old, new):
    rank = {'skip': 0, 'pass': 1, 'fail': 2}
    winner = dict(old if rank.get(old.get('status'), -1) >= rank.get(new.get('status'), -1) else new)
    winner['evidence'] = merge_list(old.get('evidence'), new.get('evidence'))
    refs = {}
    for ref in list(old.get('evidence_files', [])) + list(new.get('evidence_files', [])):
        refs[(ref.get('name'), ref.get('sha256'))] = ref
    if refs:
        winner['evidence_files'] = list(refs.values())
    details = [x for x in (old.get('detail'), new.get('detail')) if x]
    if details:
        winner['detail'] = '\n--- merged contribution ---\n'.join(dict.fromkeys(details))[-6000:]
    starts = [x for x in (old.get('started_unix_ms'), new.get('started_unix_ms')) if x is not None]
    ends = [x for x in (old.get('finished_unix_ms'), new.get('finished_unix_ms')) if x is not None]
    if starts: winner['started_unix_ms'] = min(starts)
    if ends: winner['finished_unix_ms'] = max(ends)
    return winner

by = {}
metrics = {}
for bundle in bundles:
    for name, value in bundle.get('metrics', {}).items():
        value = float(value)
        if not math.isfinite(value):
            raise SystemExit(f'non-finite metric {name}')
        if name in metrics and not math.isclose(metrics[name], value, rel_tol=1e-9, abs_tol=1e-12):
            raise SystemExit(f'conflicting metric {name}: {metrics[name]} vs {value}')
        metrics[name] = value
    for check in bundle.get('checks', []):
        old = by.get(check['id'])
        by[check['id']] = dict(check) if old is None else merge_check(old, check)

provenance_inputs = [
    {'name': path.name, 'sha256': digest(path), 'source_revision': source_revision}
    for path in inputs
]
merged = {
    'format_version': 1,
    'release': release,
    'protocol': protocol,
    'database_schema': schema,
    'generated_unix_ms': int(time.time() * 1000),
    'bundle_id': str(uuid.uuid4()),
    'source_revision': source_revision,
    'provenance': {'runner': 'merge_results.py', 'environment': {}, 'inputs': provenance_inputs},
    'checks': sorted(by.values(), key=lambda x: x['id']),
    'metrics': metrics,
}
out.write_text(json.dumps(merged, indent=2, sort_keys=True) + '\n')
print(out)
