#!/usr/bin/env python3
"""Offline SparkBridge CAS reachability GC. Stop sparkbridge-server before --delete.

Fail-closed by construction: any uncertainty about reachability (unreadable table,
unparsable record, a live object too large to traverse) aborts instead of shrinking the
root set, because a shrunken root set turns live state into deletable garbage.
"""
from __future__ import annotations
import argparse, json, pathlib, re, sqlite3, sys
DIGEST_RE=re.compile(r"^sha256:([0-9a-fA-F]{64})$")
HEX_RE=re.compile(r"^[0-9a-fA-F]{64}$")

# Tables that hold a bare digest column pointing at a CAS object.
DIGEST_COLUMNS=[
    ('snapshots','manifest_digest'),('candidates','manifest_digest'),
    ('repository_indexes','index_digest'),('native_intelligence','report_digest'),
]
# Tables whose JSON record embeds digests. `promotions` belongs here: base/observed/result
# manifest digests live only inside `record_json`, so omitting it made promoted manifests
# collectable while the promotion history still referenced them.
RECORD_JSON_TABLES=['action_cache','actions','validation_runs','tasks','promotions']

class GcAbort(SystemExit):
    """Raised when reachability cannot be determined safely; never downgraded to a warning."""

def normalize(v:str):
    m=DIGEST_RE.match(v)
    if m:return m.group(1).lower()
    if HEX_RE.match(v):return v.lower()
    return None

def collect_json(obj, out:set[str]):
    if isinstance(obj,dict):
        for k,v in obj.items():
            if isinstance(v,str) and ('digest' in k.lower() or k.lower().endswith('_sha256')):
                d=normalize(v)
                if d:out.add(d)
            collect_json(v,out)
    elif isinstance(obj,list):
        for v in obj:collect_json(v,out)

def object_path(cas:pathlib.Path,h:str)->pathlib.Path:
    return cas/'sha256'/h[:2]/h[2:4]/h

def open_readonly(db:pathlib.Path)->sqlite3.Connection:
    """Open the state database strictly read-only.

    GC must never be able to write to (or create WAL sidecars next to) a live server's
    database, so the connection is read-only and additionally pinned with query_only.
    """
    try:
        conn=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
    except sqlite3.Error as exc:
        raise GcAbort(f'refusing to open {db} read-only: {exc}')
    conn.execute('PRAGMA query_only = ON')
    return conn

def seed_roots(db:pathlib.Path)->set[str]:
    conn=open_readonly(db); roots=set()
    try:
        for table,col in DIGEST_COLUMNS:
            try:
                for (v,) in conn.execute(f'SELECT {col} FROM {table}'):
                    if isinstance(v,str):
                        d=normalize(v)
                        if d:roots.add(d)
            except sqlite3.OperationalError as exc:
                raise GcAbort(f'cannot read reachability root {table}.{col}: {exc}')
        for table in RECORD_JSON_TABLES:
            try:
                rows=list(conn.execute(f'SELECT record_json FROM {table}'))
            except sqlite3.OperationalError as exc:
                raise GcAbort(f'cannot read reachability root {table}.record_json: {exc}')
            for (raw,) in rows:
                try: collect_json(json.loads(raw),roots)
                except Exception as exc:
                    # An unparsable record could hide live digests; treat it as a blocker.
                    raise GcAbort(f'unparsable record in {table}: {exc}')
    finally:
        conn.close()
    return roots

def expand(cas:pathlib.Path, roots:set[str], max_traversable_bytes:int)->set[str]:
    live=set(); queue=list(roots)
    while queue:
        h=queue.pop()
        if h in live:continue
        live.add(h); p=object_path(cas,h)
        if not p.is_file():continue
        size=p.stat().st_size
        if size>max_traversable_bytes:
            # Descending is impossible, so this object's children would look unreachable.
            # Refuse rather than silently orphan them.
            raise GcAbort(f'live object {h} is {size} bytes, above the {max_traversable_bytes} byte traversal limit; '
                          'raise --max-traversable-bytes to match cas_max_object_bytes')
        try:
            obj=json.loads(p.read_bytes())
        except json.JSONDecodeError:
            continue  # CAS leaf payloads (file blobs) are not manifests; they have no children.
        except OSError as exc:
            raise GcAbort(f'cannot read live object {h}: {exc}')
        found=set(); collect_json(obj,found)
        for child in found:
            if child not in live:queue.append(child)
    return live

def all_objects(cas:pathlib.Path):
    base=cas/'sha256'
    if not base.exists():return []
    return [p for p in base.rglob('*') if p.is_file() and p.parent.name!='.tmp' and HEX_RE.match(p.name)]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--database',required=True,type=pathlib.Path); ap.add_argument('--cas',required=True,type=pathlib.Path); ap.add_argument('--delete',action='store_true'); ap.add_argument('--min-age-seconds',type=int,default=86400)
    ap.add_argument('--max-traversable-bytes',type=int,default=128*1024*1024,help='must be >= cas_max_object_bytes')
    ap.add_argument('--confirm-server-stopped',action='store_true',help='required with --delete: asserts sparkbridge-server is not running against this database')
    args=ap.parse_args()
    if not args.database.is_file():sys.exit('database not found')
    if args.delete:
        # Enforceable form of "must not run destructively against a live server".
        if not args.confirm_server_stopped:sys.exit('refusing to delete: re-run with --confirm-server-stopped after stopping sparkbridge-server')
        if args.min_age_seconds<=0:sys.exit('refusing to delete: --min-age-seconds must be greater than zero so recent writes are never collected')
    roots=seed_roots(args.database); live=expand(args.cas,roots,args.max_traversable_bytes); objects=all_objects(args.cas)
    import time
    cutoff=time.time()-max(0,args.min_age_seconds); garbage=[]
    for p in objects:
        if p.name not in live and p.stat().st_mtime<cutoff:garbage.append(p)
    bytes_total=sum(p.stat().st_size for p in garbage)
    print(json.dumps({'roots':len(roots),'reachable':len(live),'objects':len(objects),'garbage_objects':len(garbage),'garbage_bytes':bytes_total,'mode':'delete' if args.delete else 'dry_run'},indent=2))
    if args.delete:
        for p in garbage:p.unlink()
        for p in sorted((args.cas/'sha256').rglob('*'),reverse=True):
            if p.is_dir() and p.name!='.tmp':
                try:p.rmdir()
                except OSError:pass
if __name__=='__main__':main()
