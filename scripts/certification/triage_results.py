#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, subprocess, sys
p=argparse.ArgumentParser(description='Render actionable remediation guidance for 1.0 certification blockers.')
p.add_argument('--profile',type=pathlib.Path,default=pathlib.Path('config/certification/profile-1.0-candidate.json'))
p.add_argument('--results',type=pathlib.Path,required=True)
p.add_argument('--json',action='store_true'); a=p.parse_args()
profile=json.loads(a.profile.read_text()); results=json.loads(a.results.read_text()); by={c['id']:c for c in results.get('checks',[])}
commands={
'rust.linux-x86_64':'Run .github/workflows/ci.yml on ubuntu-latest for this exact revision.',
'rust.linux-aarch64-dgx':'Run .github/workflows/certification-dgx.yml on the self-hosted DGX Spark runner.',
'rust.macos-arm64':'Run CI/native certification on Apple Silicon macOS.',
'rust.windows-x86_64':'Run CI/native certification on Windows x86_64.',
'e2e.control-plane':'Run the production-equivalent control-plane E2E scenario in docs/CERTIFICATION.md.',
'e2e.agent-repair':'Run the broken-fixture agent repair scenario and attach task/action evidence.',
'fault.server-restart':'Execute the server restart scenario from scripts/certification/fault_plan.json.',
'fault.executor-disconnect':'Execute the executor disconnect scenario from scripts/certification/fault_plan.json.',
'fault.ollama-restart':'Execute the Ollama restart scenario from scripts/certification/fault_plan.json.',
'drill.backup-restore':'Run backup_restore_drill.sh plus an isolated restore of production-equivalent metadata/PKI.',
'drill.upgrade-rollback':'Perform the signed staged v0.11→v0.12 upgrade and service-manager rollback drill.',
'security.audit-chain':'Run an audit append/verify/tamper-detection runtime drill and attach logs.',
}
items=[]
for cid in profile.get('required_checks',[]):
    c=by.get(cid); status='missing' if c is None else c.get('status','missing')
    evidence_ok=bool(c and (c.get('evidence') or c.get('evidence_files')))
    if status!='pass' or (profile.get('require_evidence_for_pass') and not evidence_ok):
        items.append({'id':cid,'status':status,'detail':(c or {}).get('detail'),'next_action':commands.get(cid,'Collect valid evidence for this required gate on the exact source revision.')})
for t in profile.get('metric_thresholds',[]):
    if t.get('required') and t['metric'] not in results.get('metrics',{}): items.append({'id':'metric:'+t['metric'],'status':'missing','next_action':f"Capture and merge required metric {t['metric']}."})
summary={'release':results.get('release'),'source_revision':results.get('source_revision'),'count':len(items),'items':items}
if a.json: print(json.dumps(summary,indent=2))
else:
    print(f"# SparkBridge Certification Triage\n\nSource revision: `{summary['source_revision'] or 'missing'}`\n\nOutstanding items: **{len(items)}**\n")
    for item in items:
        print(f"## `{item['id']}`\n\nStatus: **{item['status']}**\n\nNext action: {item['next_action']}\n")
