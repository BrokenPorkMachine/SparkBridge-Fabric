#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, math, pathlib
p=argparse.ArgumentParser(description='Render current 1.0 certification blockers using the same release contract as the evaluator.')
p.add_argument('--profile',type=pathlib.Path,default=pathlib.Path('config/certification/profile-1.0-candidate.json'))
p.add_argument('--results',type=pathlib.Path,required=True)
p.add_argument('--json',action='store_true')
a=p.parse_args(); profile=json.loads(a.profile.read_text()); results=json.loads(a.results.read_text()); by={c['id']:c for c in results.get('checks',[])}
blockers=[]
def add(i,r,d=None):
    item={'id':i,'reason':r}
    if d: item['detail']=d
    blockers.append(item)
if results.get('release')!=profile.get('release'): add('identity.release','mismatch',f"expected {profile.get('release')}, got {results.get('release')}")
if results.get('protocol')!=profile.get('protocol'): add('identity.protocol','mismatch',f"expected {profile.get('protocol')}, got {results.get('protocol')}")
if results.get('database_schema')!=profile.get('database_schema'): add('identity.database_schema','mismatch',f"expected {profile.get('database_schema')}, got {results.get('database_schema')}")
if profile.get('require_source_revision') and not str(results.get('source_revision') or '').strip(): add('identity.source_revision','missing')
for cid in profile.get('required_checks',[]):
    c=by.get(cid)
    if c is None: add(cid,'missing'); continue
    if c.get('status')!='pass': add(cid,c.get('status','missing'),c.get('detail')); continue
    if profile.get('require_evidence_for_pass') and not c.get('evidence') and not c.get('evidence_files'): add(cid,'pass_without_evidence')
for threshold in profile.get('metric_thresholds',[]):
    name=threshold['metric']; value=results.get('metrics',{}).get(name)
    if value is None:
        if threshold.get('required'): add('metric:'+name,'missing')
        continue
    try: value=float(value)
    except Exception: add('metric:'+name,'invalid',str(value)); continue
    if not math.isfinite(value): add('metric:'+name,'non_finite',str(value)); continue
    if threshold.get('maximum') is not None and value>float(threshold['maximum']): add('metric:'+name,'above_maximum',f"{value} > {threshold['maximum']}")
    if threshold.get('minimum') is not None and value<float(threshold['minimum']): add('metric:'+name,'below_minimum',f"{value} < {threshold['minimum']}")
summary={'release':results.get('release'),'source_revision':results.get('source_revision'),'blocker_count':len(blockers),'blockers':blockers}
if a.json: print(json.dumps(summary,indent=2))
else:
    print(f"# SparkBridge 1.0 Release Blockers\n\nSource revision: `{summary['source_revision'] or 'missing'}`\n\nOutstanding blockers: **{len(blockers)}**\n")
    for b in blockers: print(f"- `{b['id']}` — {b['reason']}" + (f" — {b['detail']}" if b.get('detail') else ''))
