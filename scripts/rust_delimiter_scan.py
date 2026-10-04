#!/usr/bin/env python3
from __future__ import annotations
import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
PAIRS = {')': '(', ']': '[', '}': '{'}

def check(text: str):
    stack=[]; i=0; n=len(text)
    while i<n:
        c=text[i]
        if c=='/' and i+1<n and text[i+1]=='/':
            j=text.find('\n',i+2); i=n if j<0 else j+1; continue
        if c=='/' and i+1<n and text[i+1]=='*':
            depth=1; i+=2
            while i<n and depth:
                if text.startswith('/*',i): depth+=1; i+=2
                elif text.startswith('*/',i): depth-=1; i+=2
                else: i+=1
            if depth: return False, 'unclosed block comment'
            continue
        if c=='r':
            j=i+1
            while j<n and text[j]=='#': j+=1
            if j<n and text[j]=='"':
                hashes=j-(i+1); end='"'+'#'*hashes; k=text.find(end,j+1)
                if k<0: return False, 'unclosed raw string'
                i=k+len(end); continue
        if c=='b' and i+1<n and text[i+1]=='r':
            j=i+2
            while j<n and text[j]=='#': j+=1
            if j<n and text[j]=='"':
                hashes=j-(i+2); end='"'+'#'*hashes; k=text.find(end,j+1)
                if k<0: return False, 'unclosed raw byte string'
                i=k+len(end); continue
        if c=='"':
            i+=1
            while i<n:
                if text[i]=='\\': i+=2; continue
                if text[i]=='"': i+=1; break
                i+=1
            else: return False, 'unclosed string'
            continue
        if c in '([{': stack.append((c,i))
        elif c in ')]}':
            if not stack or stack[-1][0] != PAIRS[c]: return False, f'mismatched {c} at byte {i}'
            stack.pop()
        i+=1
    if stack: return False, f'unclosed delimiter {stack[-1]}'
    return True, 'ok'

failed=[]
files=sorted(ROOT.rglob('*.rs'))
for path in files:
    ok,msg=check(path.read_text())
    if not ok: failed.append((path.relative_to(ROOT),msg))
if failed:
    for p,msg in failed: print(f'FAIL: {p}: {msg}', file=sys.stderr)
    sys.exit(1)
print(f'Rust delimiter/source scan passed: {len(files)} files')
