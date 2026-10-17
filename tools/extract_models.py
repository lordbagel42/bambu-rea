#!/usr/bin/env python3
"""Extract kotlinx.serialization model classes referenced by the endpoint catalog.

Usage: extract_models.py <jadx-sources-dir> <endpoints.json> <out models.json>

For every @Serializable class reachable from endpoint bodies/responses, record its JSON
field names (from the generated `$$serializer`'s `addElement(name, optional)` calls,
matched to Kotlin properties through `get<Prop>$annotations` @SerialName markers) and
the Java type of each property. Enums record their @SerialName values.
"""
import json
import os
import re
import sys

BUILTIN = {"String", "Integer", "Long", "Boolean", "Double", "Float", "int", "long", "boolean",
           "double", "float", "Object", "JsonObject", "JsonElement", "JsonArray", "JsonPrimitive",
           "List", "Map", "Set", "pqs", "dfo", "p45", "Unit", "Any", "Short", "Byte", "Number",
           "byte", "short", "char", "Character", "BigDecimal"}

FIELD_RE = re.compile(r"^    private (?!static )(?:final |transient |volatile )*(\S.*?) (\w+);$")
ANNOT_RE = re.compile(r"@SerialName\(\"([^\"]*)\"\)")
GETTER_RE = re.compile(r"public static (?:/\* synthetic \*/ )?void (\w+)\$annotations\(\)")
ADD_RE = re.compile(r"addElement\(\"([^\"]*)\", (true|false)\)")
ENUM_RE = re.compile(r"^    public static final (\w+) (\w+) = new \1\(\"(\w+)\", (\d+)")
CLASS_RE = re.compile(r"^public (?:final |abstract )*(?:/\* data \*/ |/\* enum \*/ )?(class|interface) (\w+)(<[^>{]*>)?")


def type_names(t: str):
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", t)


def index_sources(root):
    idx = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".java"):
                idx.setdefault(f[:-5], []).append(os.path.join(dp, f))
    return idx


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def prop_from_getter(g: str):
    if g.startswith("get") and len(g) > 3:
        return g[3].lower() + g[4:]
    return g  # isXxx


IMPORT_RE = re.compile(r"^import ([\w.]+)\.(\w+);$", re.M)


def imports_of(src: str):
    return {m.group(2): m.group(1) + "." + m.group(2) for m in IMPORT_RE.finditer(src)}


def fqn_path(root, fqn):
    return os.path.join(root, *fqn.split(".")) + ".java"


def resolve(name, imports, pkg, idx, root):
    """Resolve a simple type name used inside a file to a fully-qualified class name."""
    if name in imports:
        return imports[name]
    if os.path.exists(fqn_path(root, pkg + "." + name)):
        return pkg + "." + name
    paths = idx.get(name)
    if not paths:
        return None
    paths = sorted(paths, key=lambda p: ("defpackage" in p, p))
    return os.path.relpath(paths[0], root)[:-5].replace("/", ".")


def parse_class(fqn, idx, root):
    path = fqn_path(root, fqn)
    if not os.path.exists(path):
        return None
    name = fqn.rsplit(".", 1)[-1]
    src = read(path)
    pkg = fqn.rsplit(".", 1)[0]
    lines = src.splitlines()
    kind, type_params = None, []
    for ln in lines:
        m = CLASS_RE.match(ln)
        if m:
            kind = m.group(1)
            if m.group(3):
                type_params = [t.strip().split(" ")[0] for t in m.group(3)[1:-1].split(",")]
            break
    is_enum = "Failed to restore enum class" in src or "/* enum */" in src or "$VALUES" in src
    rec = {"name": name, "package": pkg, "serializable": "@Serializable" in src, "typeParams": type_params,
           "imports": imports_of(src)}
    if is_enum:
        values = []
        pending = None
        for ln in lines:
            am = ANNOT_RE.search(ln)
            if am and "public static final" not in ln:
                pending = am.group(1)
                continue
            em = ENUM_RE.match(ln)
            if em and em.group(1) == name:
                values.append({"name": em.group(2), "json": pending if pending is not None else em.group(3)})
                pending = None
            elif ln.strip() and not ln.strip().startswith("@"):
                pending = None
        rec["kind"] = "enum"
        rec["values"] = values
        return rec
    rec["kind"] = "class"
    fields = []
    for ln in lines:
        fm = FIELD_RE.match(ln)
        if fm and fm.group(2) not in ("$stable", "Companion") and not fm.group(2).startswith("$"):
            fields.append({"prop": fm.group(2), "javaType": fm.group(1)})
    # SerialName markers
    names = {}
    pending = None
    for ln in lines:
        am = ANNOT_RE.search(ln)
        if am:
            pending = am.group(1)
            continue
        gm = GETTER_RE.search(ln)
        if gm:
            if pending is not None:
                names[prop_from_getter(gm.group(1))] = pending
            pending = None
        elif ln.strip() and not ln.strip().startswith("@") and not ln.strip().startswith("/*"):
            pending = None
    for f in fields:
        f["json"] = names.get(f["prop"], f["prop"])
    # JSON names and optionality from the generated $$serializer (authoritative; @SerialName
    # literals are sometimes replaced by inlined constants in the decompiled data class).
    ser = idx.get(name + "$$serializer")
    optional = {}
    if ser:
        for am in ADD_RE.finditer(read(ser[0])):
            optional[am.group(1)] = am.group(2) == "true"
        rec["serializerNames"] = list(optional.keys())
        fields = reconcile(fields, list(optional.keys()))
    for f in fields:
        f["optional"] = optional.get(f["json"], True)
    rec["fields"] = fields
    return rec


def norm(s: str):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def reconcile(fields, ser_names):
    """Match Kotlin properties to serializer element names; drop @Transient properties."""
    by_json = {}
    for f in fields:
        by_json.setdefault(f["json"], f)
    out, used = [], set()
    for n in ser_names:
        f = by_json.get(n)
        if f is None or id(f) in used:
            cands = [g for g in fields if id(g) not in used and (
                norm(g["prop"]) == norm(n)
                or (g["prop"].startswith("is") and norm(g["prop"][2:]) == norm(n))
                or norm(g["prop"]) == norm("is" + n))]
            f = cands[0] if len(cands) == 1 else None
        if f is None:
            out.append({"prop": n, "javaType": "Object", "json": n, "unmatched": True})
            continue
        used.add(id(f))
        out.append({**f, "json": n})
    return out


def main():
    root, eps_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
    idx = index_sources(root)
    eps = json.load(open(eps_path))["endpoints"]
    queue, endpoint_refs, iface_cache = [], {}, {}
    for e in eps:
        iface = e["interface"]
        if iface not in iface_cache:
            ipath = fqn_path(root, iface)
            isrc = read(ipath) if os.path.exists(ipath) else ""
            iface_cache[iface] = (imports_of(isrc), iface.rsplit(".", 1)[0])
        imports, pkg = iface_cache[iface]
        refs = endpoint_refs.setdefault(iface, {})
        names = type_names(e["response"])
        for p in e["params"]:
            if p["kind"] == "body":
                names += type_names(p["javaType"])
        for n in names:
            if n in BUILTIN or len(n) <= 2:
                continue
            fqn = resolve(n, imports, pkg, idx, root)
            if fqn:
                refs[n] = fqn
                queue.append(fqn)
    seen, models, missing = set(), {}, []
    while queue:
        fqn = queue.pop()
        if fqn in seen:
            continue
        seen.add(fqn)
        rec = parse_class(fqn, idx, root)
        if rec is None:
            missing.append(fqn)
            continue
        models[fqn] = rec
        refs = {}
        if rec["kind"] == "class":
            for f in rec["fields"]:
                for t in type_names(f["javaType"]):
                    if t in rec["typeParams"] or t in BUILTIN or len(t) <= 2 or t in refs:
                        continue
                    r = resolve(t, rec["imports"], rec["package"], idx, root)
                    if r:
                        refs[t] = r
                        queue.append(r)
        rec["refs"] = refs
        del rec["imports"]
    json.dump({"models": models, "endpointRefs": endpoint_refs, "missing": sorted(missing)}, open(out, "w"), indent=1)
    classes = sum(1 for m in models.values() if m["kind"] == "class")
    enums = len(models) - classes
    unmatched = sum(1 for m in models.values() if m["kind"] == "class" and m.get("serializerNames")
                    and set(m["serializerNames"]) != {f["json"] for f in m["fields"]})
    print(f"{classes} classes, {enums} enums, {len(missing)} missing, {unmatched} with serializer/field name mismatch -> {out}")


if __name__ == "__main__":
    main()
