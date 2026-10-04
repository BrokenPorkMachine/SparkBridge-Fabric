#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, shutil
from common import ROOT, environment, evidence_ref, new_bundle_id, now_ms, runner_name, source_revision, write_json

p=argparse.ArgumentParser(description='Record one certification check with hashed evidence.')
p.add_argument('--results', type=pathlib.Path, required=True)
p.add_argument('--check', required=True)
p.add_argument('--status', choices=['pass','fail','skip'], required=True)
p.add_argument('--platform')
p.add_argument('--detail')
p.add_argument('--command')
p.add_argument('--evidence', action='append', type=pathlib.Path, default=[])
p.add_argument('--started-unix-ms', type=int)
p.add_argument('--finished-unix-ms', type=int)
a=p.parse_args()
if a.results.exists(): obj=json.loads(a.results.read_text())
else:
    obj=json.loads((ROOT/'config/certification/results-template.json').read_text())
    obj['generated_unix_ms']=now_ms(); obj['bundle_id']=new_bundle_id(); obj['source_revision']=source_revision(); obj['provenance']={'runner':runner_name(),'environment':environment(),'inputs':[]}
checks={c['id']:c for c in obj['checks']}
if a.check not in checks: raise SystemExit(f'unknown check id: {a.check}')
check=checks[a.check]; check['status']=a.status
if a.platform: check['platform']=a.platform
if a.detail: check['detail']=a.detail
if a.command: check['command']=a.command; check['evidence']=[a.command]
if a.started_unix_ms is not None: check['started_unix_ms']=a.started_unix_ms
if a.finished_unix_ms is not None: check['finished_unix_ms']=a.finished_unix_ms
refs=[]
for path in a.evidence:
    path=path.resolve()
    if not path.is_file(): raise SystemExit(f'evidence not found: {path}')
    refs.append(evidence_ref(path, ROOT))
if refs: check['evidence_files']=refs
obj['generated_unix_ms']=now_ms(); obj['source_revision']=obj.get('source_revision') or source_revision(); obj['bundle_id']=obj.get('bundle_id') or new_bundle_id()
obj['provenance']=obj.get('provenance') or {'runner':runner_name(),'environment':environment(),'inputs':[]}
write_json(a.results,obj); print(a.results)
