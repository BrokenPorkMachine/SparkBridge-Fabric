#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,ssl,urllib.request
p=argparse.ArgumentParser(); p.add_argument('--admin',default='http://127.0.0.1:7787'); p.add_argument('--integration'); p.add_argument('--integration-token'); p.add_argument('--gateway'); p.add_argument('--gateway-token'); p.add_argument('--ca'); a=p.parse_args()
ctx=ssl.create_default_context(cafile=a.ca) if a.ca else ssl.create_default_context()
def get(url,token=None):
    req=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}'} if token else {})
    with urllib.request.urlopen(req,context=ctx,timeout=10) as r: return r.status,json.loads(r.read().decode())
results={}
results['admin_health']=get(a.admin.rstrip('/')+'/health')
if a.integration: results['integration_summary']=get(a.integration.rstrip('/')+'/api/v1/integrations/summary',a.integration_token)
if a.gateway: results['inference_health']=get(a.gateway.rstrip('/')+'/api/v1/inference/health',a.gateway_token)
print(json.dumps(results,indent=2))
