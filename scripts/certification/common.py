from __future__ import annotations
import hashlib, json, os, pathlib, platform, subprocess, sys, time, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
DYNAMIC_NAMES = {
    'certification-results.local.json',
    'certification-results.json',
    'certification-report.json',
    'CERTIFICATION_STATUS.md',
    'VALIDATION.md',
    'PROJECT_FILES.txt',
    'manifest.json',
    # OS/tooling droppings are not source and must not change the certified revision.
    '.DS_Store',
    'Thumbs.db',
    'desktop.ini',
}
DYNAMIC_PREFIXES = ('certification-results.',)
DYNAMIC_SUFFIXES = ('.zip', '.zip.sha256')
DYNAMIC_DIRS = ('.git/', 'target/', '.venv/', '.pytest_cache/', 'certification-evidence/', 'certification-run/', '.idea/', '.vscode/')


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def source_revision(root: pathlib.Path = ROOT) -> str:
    git = root / '.git'
    if git.exists():
        try:
            value = subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, stderr=subprocess.DEVNULL
            ).strip()
            if value:
                return f'git:{value}'
        except Exception:
            pass

    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(DYNAMIC_DIRS):
            continue
        if '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo'):
            continue
        if path.name in DYNAMIC_NAMES or path.name.startswith(DYNAMIC_PREFIXES) or path.name.endswith(DYNAMIC_SUFFIXES):
            continue
        h.update(rel.encode('utf-8'))
        h.update(b'\0')
        h.update(path.read_bytes())
        h.update(b'\0')
    return f'tree-sha256:{h.hexdigest()}'


def environment() -> dict[str, str]:
    env = {
        'os': platform.system(),
        'os_release': platform.release(),
        'architecture': platform.machine(),
        'python': platform.python_version(),
    }
    for command in ('cargo', 'rustc'):
        try:
            env[command] = subprocess.check_output([command, '--version'], text=True, stderr=subprocess.STDOUT).strip()
        except Exception:
            env[command] = 'unavailable'
    return env


def now_ms() -> int:
    return int(time.time() * 1000)


def new_bundle_id() -> str:
    return str(uuid.uuid4())


def write_json(path: pathlib.Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def evidence_ref(path: pathlib.Path, root: pathlib.Path = ROOT) -> dict[str, object]:
    name = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
    return {
        'name': name,
        'sha256': sha256_file(path),
        'size_bytes': path.stat().st_size,
        'media_type': 'text/plain' if path.suffix in ('.log', '.txt', '.md') else 'application/octet-stream',
    }


def platform_check_id() -> str | None:
    os_name = platform.system().lower()
    arch = platform.machine().lower()
    if os_name == 'linux' and arch in ('x86_64', 'amd64'):
        return 'rust.linux-x86_64'
    if os_name == 'linux' and arch in ('aarch64', 'arm64'):
        return 'rust.linux-aarch64-dgx'
    if os_name == 'darwin' and arch in ('arm64', 'aarch64'):
        return 'rust.macos-arm64'
    if os_name == 'windows' and arch in ('x86_64', 'amd64'):
        return 'rust.windows-x86_64'
    return None


def runner_name() -> str:
    return os.environ.get('SPARKBRIDGE_CERT_RUNNER') or os.environ.get('RUNNER_NAME') or platform.node() or 'unknown-runner'
