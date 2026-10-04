#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib
ap=argparse.ArgumentParser(); ap.add_argument('artifact',type=pathlib.Path); ap.add_argument('--version',required=True); ap.add_argument('--minimum-protocol',default='1.10'); ap.add_argument('--output',type=pathlib.Path,default=pathlib.Path('update-manifest.json')); a=ap.parse_args()
b=a.artifact.read_bytes(); obj={'format_version':1,'version':a.version,'artifact_name':a.artifact.name,'artifact_sha256':hashlib.sha256(b).hexdigest(),'artifact_size':len(b),'minimum_protocol':a.minimum_protocol}; a.output.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n'); print(a.output)
