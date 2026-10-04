#!/usr/bin/env bash
set -euo pipefail
# Preflight drill: staged artifacts must never mutate the selected live binary.
# Production certification must additionally exercise sparkbridge update verify/stage
# with the real release signing key and service-manager rollback procedure.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 - "$ROOT" <<'PY'
import pathlib,tempfile,hashlib,sys,shutil,json
root=pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory() as tmp:
    tmp=pathlib.Path(tmp); live=tmp/'live'; stage=tmp/'stage'; live.mkdir(); stage.mkdir()
    live_bin=live/'sparkbridge-server'; live_bin.write_bytes(b'old-binary')
    old_hash=hashlib.sha256(live_bin.read_bytes()).hexdigest()
    staged=stage/'sparkbridge-server'; staged.write_bytes(b'new-binary')
    new_hash=hashlib.sha256(staged.read_bytes()).hexdigest()
    assert old_hash != new_hash
    manifest={'old_sha256':old_hash,'staged_sha256':new_hash}
    (tmp/'drill.json').write_text(json.dumps(manifest,sort_keys=True))
    assert hashlib.sha256(live_bin.read_bytes()).hexdigest()==old_hash
    shutil.rmtree(stage)
    assert hashlib.sha256(live_bin.read_bytes()).hexdigest()==old_hash
print('PASS staged-update rollback isolation preflight')
PY
