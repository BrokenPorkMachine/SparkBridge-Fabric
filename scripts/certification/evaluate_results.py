#!/usr/bin/env python3
from __future__ import annotations
import json, math, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
profile = json.loads(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'config/certification/profile-1.0-candidate.json').read_text())
results = json.loads(pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else ROOT / 'config/certification/results-template.json').read_text())
fail=[]; warn=[]
if results.get('release') != profile['release']: fail.append('release mismatch')
if results.get('protocol') != profile['protocol']: fail.append('protocol mismatch')
if results.get('database_schema') != profile['database_schema']: fail.append('schema mismatch')
if profile.get('require_source_revision') and not str(results.get('source_revision') or '').strip(): fail.append('missing required source_revision')
by={}
for check in results.get('checks', []):
    cid=check['id']
    if cid in by: fail.append(f'duplicate check id: {cid}')
    by[cid]=check
    start=check.get('started_unix_ms'); finish=check.get('finished_unix_ms')
    if start is not None and finish is not None and finish < start: fail.append(f'{cid}: finished before started')
    for evidence in check.get('evidence_files', []):
        sha=str(evidence.get('sha256',''))
        if len(sha)!=64 or any(c not in '0123456789abcdefABCDEF' for c in sha): fail.append(f'{cid}: invalid evidence digest')
for cid in profile['required_checks']:
    check=by.get(cid)
    if not check: fail.append(f'missing required check: {cid}'); continue
    if check.get('status') != 'pass': fail.append(f"{cid}: {check.get('status','missing')}"); continue
    if profile.get('require_evidence_for_pass') and not check.get('evidence') and not check.get('evidence_files'):
        fail.append(f'{cid}: pass has no evidence')
metrics=results.get('metrics', {})
for threshold in profile.get('metric_thresholds', []):
    name=threshold['metric']; value=metrics.get(name)
    if value is None:
        if threshold.get('required'): fail.append(f'missing required metric: {name}')
        else: warn.append(f'optional metric not reported: {name}')
        continue
    value=float(value)
    if not math.isfinite(value): fail.append(f'{name}: non-finite'); continue
    if threshold.get('maximum') is not None and value > threshold['maximum']: fail.append(f"{name}={value} > {threshold['maximum']}")
    if threshold.get('minimum') is not None and value < threshold['minimum']: fail.append(f"{name}={value} < {threshold['minimum']}")
report={'release_ready':not fail,'failures':fail,'warnings':warn,'passed':sum(1 for x in by.values() if x.get('status')=='pass'),'failed':sum(1 for x in by.values() if x.get('status')=='fail'),'skipped':sum(1 for x in by.values() if x.get('status')=='skip'),'source_revision':results.get('source_revision'),'bundle_id':results.get('bundle_id')}
print(json.dumps(report, indent=2))
sys.exit(0 if not fail else 2)
