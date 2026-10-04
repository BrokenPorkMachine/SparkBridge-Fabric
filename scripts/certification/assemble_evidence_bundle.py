#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
p=argparse.ArgumentParser(description='Assemble same-revision result bundles and their evidence into one portable directory.')
p.add_argument('--output-dir', type=pathlib.Path, required=True)
p.add_argument('inputs', nargs='+', type=pathlib.Path)
a=p.parse_args(); out=a.output_dir.resolve(); out.mkdir(parents=True,exist_ok=True)
inputs_dir=out/'inputs'; evidence_dir=out/'evidence'; inputs_dir.mkdir(exist_ok=True); evidence_dir.mkdir(exist_ok=True)
rewritten=[]

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

for src in a.inputs:
    src=src.resolve(); obj=json.loads(src.read_text()); prefix=f"{src.stem}-{sha(src)[:12]}"
    copied_bundle=inputs_dir/f'{prefix}.json'; shutil.copy2(src,copied_bundle)
    for check in obj.get('checks',[]):
        new_refs=[]
        for ref in check.get('evidence_files',[]):
            name=ref.get('name')
            if not name: raise SystemExit(f'{src}: evidence reference without name')
            candidate=(src.parent/name).resolve()
            if not candidate.is_file():
                # CI artifacts commonly place the bundle next to certification-evidence/.
                candidate=(src.parent/'certification-evidence'/pathlib.Path(name).name).resolve()
            if not candidate.is_file(): raise SystemExit(f'{src}: missing evidence {name}')
            actual=sha(candidate)
            if actual.lower()!=str(ref.get('sha256','')).lower(): raise SystemExit(f'{src}: evidence digest mismatch for {name}')
            if int(ref.get('size_bytes',candidate.stat().st_size))!=candidate.stat().st_size: raise SystemExit(f'{src}: evidence size mismatch for {name}')
            dest=evidence_dir/prefix/pathlib.Path(name).name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(candidate,dest)
            new=dict(ref); new['name']=dest.relative_to(out).as_posix(); new_refs.append(new)
        check['evidence_files']=new_refs
    temp=inputs_dir/f'{prefix}.rewritten.json'; temp.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n'); rewritten.append(temp)

merged=out/'certification-results.json'
subprocess.run([sys.executable,str(HERE/'merge_results.py'),str(merged),*[str(x) for x in rewritten]],check=True,cwd=ROOT)
# Make provenance inputs portable inside the assembled directory.
obj=json.loads(merged.read_text())
obj['provenance']['inputs']=[{'name':p.relative_to(out).as_posix(),'sha256':sha(p),'source_revision':obj.get('source_revision')} for p in sorted(inputs_dir.glob('*.json')) if not p.name.endswith('.rewritten.json')]
merged.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
for temp in rewritten: temp.unlink(missing_ok=True)
subprocess.run([sys.executable,str(HERE/'verify_evidence_bundle.py'),'--results',str(merged),'--root',str(out)],check=True,cwd=ROOT)
manifest={'format_version':1,'source_revision':obj.get('source_revision'),'results_sha256':sha(merged),'files':[]}
for path in sorted(p for p in out.rglob('*') if p.is_file()):
    manifest['files'].append({'name':path.relative_to(out).as_posix(),'sha256':sha(path),'size_bytes':path.stat().st_size})
(out/'evidence-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
print(out)
