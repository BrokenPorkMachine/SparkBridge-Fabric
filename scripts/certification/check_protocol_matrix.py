#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
obj=json.loads((ROOT/'config/certification/protocol-matrix.json').read_text())
major,minor=map(int,obj['server_protocol'].split('.'))
for case in obj['cases']:
    cmaj,cmin=map(int,case['client'].split('.'))
    compatible=(cmaj==major)
    negotiated=f"{major}.{min(minor,cmin)}" if compatible else None
    if compatible != case['compatible'] or negotiated != case['negotiated']:
        raise SystemExit(f"protocol matrix mismatch for {case['client']}: got compatible={compatible}, negotiated={negotiated}")
    print(f"PASS protocol {case['client']} -> {negotiated if negotiated else 'incompatible'}")
print('protocol compatibility matrix passed')
