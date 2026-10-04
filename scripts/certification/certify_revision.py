#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, shutil, subprocess, sys, tempfile
HERE=pathlib.Path(__file__).resolve().parent; ROOT=HERE.parents[1]
p=argparse.ArgumentParser(description='One-command SparkBridge certification collection/evaluation for one exact source revision.')
p.add_argument('--output-dir',type=pathlib.Path,default=ROOT/'certification-run')
p.add_argument('--input',action='append',type=pathlib.Path,default=[],help='Additional same-revision result bundle (repeatable).')
p.add_argument('--skip-local',action='store_true')
p.add_argument('--require-ready',action='store_true')
a=p.parse_args(); out=a.output_dir.resolve(); out.mkdir(parents=True,exist_ok=True)
inputs=[]
if not a.skip_local:
    subprocess.run([sys.executable,str(HERE/'generate_local_results.py')],check=True,cwd=ROOT)
    local=ROOT/'certification-results.local.json'; inputs.append(local)
inputs.extend(x.resolve() for x in a.input)
if not inputs: raise SystemExit('no certification inputs supplied')
assembled=out/'bundle'
if assembled.exists(): shutil.rmtree(assembled)
subprocess.run([sys.executable,str(HERE/'assemble_evidence_bundle.py'),'--output-dir',str(assembled),*[str(x) for x in inputs]],check=True,cwd=ROOT)
results=assembled/'certification-results.json'; profile=ROOT/'config/certification/profile-1.0-candidate.json'
blockers_json=out/'release-blockers.json'; blockers_md=out/'release-blockers.md'; triage=out/'triage.md'
with blockers_json.open('w') as f: subprocess.run([sys.executable,str(HERE/'release_blockers.py'),'--profile',str(profile),'--results',str(results),'--json'],check=True,cwd=ROOT,stdout=f)
with blockers_md.open('w') as f: subprocess.run([sys.executable,str(HERE/'release_blockers.py'),'--profile',str(profile),'--results',str(results)],check=True,cwd=ROOT,stdout=f)
with triage.open('w') as f: subprocess.run([sys.executable,str(HERE/'triage_results.py'),'--profile',str(profile),'--results',str(results)],check=True,cwd=ROOT,stdout=f)
summary=json.loads(blockers_json.read_text()); report={'release_ready':summary.get('blocker_count',0)==0,'source_revision':summary.get('source_revision'),'blocker_count':summary.get('blocker_count',0),'results':results.relative_to(out).as_posix(),'blockers':blockers_md.name,'triage':triage.name}
(out/'certification-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report,indent=2))
if a.require_ready and not report['release_ready']: raise SystemExit(2)
