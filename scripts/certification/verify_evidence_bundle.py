#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys

p=argparse.ArgumentParser(description='Verify all evidence files referenced by a SparkBridge certification bundle.')
p.add_argument('--results', type=pathlib.Path, required=True)
p.add_argument('--root', type=pathlib.Path, default=pathlib.Path('.'))
a=p.parse_args()
root=a.root.resolve(); obj=json.loads(a.results.read_text())
errors=[]; verified=0
for check in obj.get('checks',[]):
    for ref in check.get('evidence_files',[]):
        name=ref.get('name'); expected=ref.get('sha256'); expected_size=ref.get('size_bytes')
        if not name or not expected:
            errors.append(f"{check.get('id')}: malformed evidence reference")
            continue
        path=(root/name).resolve()
        try: path.relative_to(root)
        except ValueError:
            errors.append(f"{check.get('id')}: evidence escapes root: {name}"); continue
        if not path.is_file():
            errors.append(f"{check.get('id')}: missing evidence file: {name}"); continue
        data=path.read_bytes(); digest=hashlib.sha256(data).hexdigest()
        if digest.lower()!=str(expected).lower():
            errors.append(f"{check.get('id')}: digest mismatch for {name}: {digest} != {expected}")
        if expected_size is not None and len(data)!=int(expected_size):
            errors.append(f"{check.get('id')}: size mismatch for {name}: {len(data)} != {expected_size}")
        verified+=1
for inp in obj.get('provenance',{}).get('inputs',[]):
    name=inp.get('name'); expected=inp.get('sha256')
    if not name or not expected: continue
    path=(root/name).resolve()
    try: path.relative_to(root)
    except ValueError:
        errors.append(f"provenance input escapes root: {name}"); continue
    if path.is_file():
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest.lower()!=str(expected).lower(): errors.append(f"provenance digest mismatch for {name}")
if errors:
    print('\n'.join('FAIL: '+e for e in errors), file=sys.stderr)
    raise SystemExit(1)
print(f'PASS: verified {verified} evidence file reference(s)')
