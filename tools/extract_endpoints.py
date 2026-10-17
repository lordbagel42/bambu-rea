#!/usr/bin/env python3
"""Extract the Retrofit endpoint catalog from the jadx-decompiled Bambu Handy sources.

Usage: extract_endpoints.py <jadx-sources-dir> <out.json>

The APK is R8-obfuscated, so Retrofit's annotation classes have short names.
Mapping (verified against retrofit2.http semantics in the decompiled code):
  ipd=GET vok=POST wok=PUT vw7=DELETE tok=PATCH f8e=HTTP(method,path,hasBody)
  lyk=Path fbn=Query hbn=QueryMap vae=Header fh4=Body wvs=Url vbr=Tag bbe=Headers
Kotlin suspend functions appear as `Object name(..., oe7<? super T> oe7Var)`; T is the
response type.
"""
import json
import os
import re
import sys

HTTP_ANN = {"ipd": "GET", "vok": "POST", "wok": "PUT", "vw7": "DELETE", "tok": "PATCH"}
PARAM_ANN = {"lyk": "path", "fbn": "query", "hbn": "querymap", "vae": "header", "fh4": "body",
             "wvs": "url", "vbr": "tag"}

ANN_RE = re.compile(r"^\s*@(\w+)(?:\((.*)\))?\s*$")
F8E_RE = re.compile(r'hasBody\s*=\s*(true|false).*?method\s*=\s*"(\w+)".*?path\s*=\s*"([^"]*)"')
SIG_RE = re.compile(r"^\s*(?:public\s+)?(?:abstract\s+)?(.+?)\s+(\w+)\((.*)\);\s*$")


def split_top(s: str):
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def parse_param(p: str):
    kind, name, extra = None, None, {}
    m = re.match(r"^@(\w+)(?:\((.*?)\))?\s+(.*)$", p)
    if m:
        ann, args, rest = m.groups()
        kind = PARAM_ANN.get(ann, ann)
        if args:
            mm = re.search(r'"([^"]*)"', args)
            if mm:
                name = mm.group(1)
            if "encoded = true" in args:
                extra["encoded"] = True
        p = rest
    toks = p.rsplit(" ", 1)
    jtype = toks[0].strip() if len(toks) == 2 else p
    var = toks[1] if len(toks) == 2 else ""
    return {"kind": kind, "name": name, "javaType": jtype, "var": var, **extra}


def parse_file(path: str, root: str):
    rel = os.path.relpath(path, root)
    cls = rel[:-5].replace("/", ".")
    endpoints = []
    pending = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.lstrip().startswith("@Metadata") or line.lstrip().startswith("import "):
                continue
            am = ANN_RE.match(line)
            if am:
                pending.append((am.group(1), am.group(2) or ""))
                continue
            sm = SIG_RE.match(line)
            if sm and pending:
                ret, mname, params = sm.groups()
                http, hpath, has_body, headers = None, None, None, []
                for ann, args in pending:
                    if ann in HTTP_ANN:
                        http = HTTP_ANN[ann]
                        hpath = re.search(r'"([^"]*)"', args).group(1) if '"' in args else ""
                    elif ann == "f8e":
                        fm = F8E_RE.search(args)
                        if fm:
                            has_body, http, hpath = fm.group(1) == "true", fm.group(2), fm.group(3)
                    elif ann == "bbe":
                        headers = re.findall(r"[\w.]+|\"[^\"]*\"", args)
                if http is None:
                    pending = []
                    continue
                plist = [parse_param(p) for p in split_top(params)]
                resp = None
                real_params = []
                for p in plist:
                    if p["javaType"].startswith("oe7<"):
                        mm = re.match(r"oe7<\?\s*super\s+(.*)>$", p["javaType"])
                        resp = mm.group(1) if mm else p["javaType"]
                    else:
                        real_params.append(p)
                if resp is None:
                    resp = ret
                endpoints.append({
                    "interface": cls,
                    "method": mname,
                    "http": http,
                    "path": hpath,
                    "hasBody": has_body if has_body is not None else any(p["kind"] == "body" for p in real_params),
                    "params": real_params,
                    "response": resp,
                    "staticHeaders": headers,
                })
            pending = []
    return endpoints


def main():
    root, out = sys.argv[1], sys.argv[2]
    eps = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".java"):
                p = os.path.join(dirpath, f)
                with open(p, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(200000)
                if not re.search(r"^\s*@(ipd|vok|wok|vw7|tok|f8e)\(", head, re.M):
                    continue
                eps.extend(parse_file(p, root))
    eps.sort(key=lambda e: (e["path"], e["http"], e["interface"], e["method"]))
    with open(out, "w") as fh:
        json.dump({"source": "Bambu Handy 4.2.2 (bbl.intl.bambulab.com), jadx 1.5.5 + Virbox string decryption",
                   "endpoints": eps}, fh, indent=1)
    print(f"{len(eps)} endpoints from {len({e['interface'] for e in eps})} interfaces -> {out}")


if __name__ == "__main__":
    main()
