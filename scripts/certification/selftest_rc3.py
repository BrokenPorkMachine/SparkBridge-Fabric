#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, subprocess, sys, tempfile
from common import ROOT, source_revision

HERE=pathlib.Path(__file__).resolve().parent

def run(args, ok=True):
    p=subprocess.run(args,cwd=ROOT,text=True,capture_output=True)
    if ok and p.returncode!=0: raise SystemExit(f"expected success: {' '.join(map(str,args))}\n{p.stdout}{p.stderr}")
    if not ok and p.returncode==0: raise SystemExit(f"expected failure: {' '.join(map(str,args))}")
    return p

before=source_revision()
tmp_marker=ROOT/'certification-run'/'selftest-marker.txt'; tmp_marker.parent.mkdir(parents=True,exist_ok=True); tmp_marker.write_text('generated output\n')
after=source_revision(); tmp_marker.unlink();
if before!=after: raise SystemExit('certification-run changed source revision')

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td); ev=td/'evidence.log'; ev.write_text('evidence\n')
    import hashlib
    digest=hashlib.sha256(ev.read_bytes()).hexdigest()
    bundle={
      'format_version':1,'release':'0.12.0','protocol':'1.10','database_schema':9,'generated_unix_ms':1,
      'source_revision':before,'provenance':{'runner':'selftest','environment':{},'inputs':[]},
      'checks':[{'id':'source.audit','status':'pass','evidence':['selftest'],'evidence_files':[{'name':'evidence.log','sha256':digest,'size_bytes':ev.stat().st_size}]}],
      'metrics':{}
    }
    b=td/'results.json'; b.write_text(json.dumps(bundle))
    run([sys.executable,str(HERE/'verify_evidence_bundle.py'),'--results',str(b),'--root',str(td)])
    ev.write_text('tampered\n')
    run([sys.executable,str(HERE/'verify_evidence_bundle.py'),'--results',str(b),'--root',str(td)],ok=False)

    profile={'format_version':1,'release':'0.12.0','protocol':'1.10','database_schema':9,'required_checks':['source.audit'],'metric_thresholds':[{'metric':'x','maximum':1.0,'required':True}],'require_source_revision':True,'require_evidence_for_pass':True}
    pf=td/'profile.json'; pf.write_text(json.dumps(profile))
    bundle['metrics']={'x':2.0}; b.write_text(json.dumps(bundle))
    p=run([sys.executable,str(HERE/'release_blockers.py'),'--profile',str(pf),'--results',str(b),'--json'])
    obj=json.loads(p.stdout)
    if not any(x['id']=='metric:x' for x in obj['blockers']): raise SystemExit('metric blocker missing')

print('PASS: rc3 certification tooling self-test')
