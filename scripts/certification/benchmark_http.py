#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, statistics, ssl, time, urllib.request
p=argparse.ArgumentParser(); p.add_argument('url'); p.add_argument('--samples',type=int,default=30); p.add_argument('--token'); p.add_argument('--ca'); p.add_argument('--metric',default='control_health_p95_ms'); a=p.parse_args()
ctx=ssl.create_default_context(cafile=a.ca) if a.ca else ssl.create_default_context()
values=[]
for _ in range(a.samples):
    req=urllib.request.Request(a.url,headers={'Authorization':f'Bearer {a.token}'} if a.token else {})
    t=time.perf_counter()
    with urllib.request.urlopen(req,context=ctx,timeout=10) as r: r.read()
    values.append((time.perf_counter()-t)*1000)
values.sort(); idx=max(0,min(len(values)-1,int(0.95*len(values)+0.999999)-1)); p95=values[idx]
print(json.dumps({'metric':a.metric,'samples':len(values),'median_ms':statistics.median(values),'p95_ms':p95,'min_ms':min(values),'max_ms':max(values)},indent=2))
