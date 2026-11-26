#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1239 (#260) diff two `perf report --stdio --sort comm,dso,sym` files in absolute cycles.

Each line's percentage times the report's event count gives its cycles; engine binaries are folded to
"gotatun" and Rust v0 symbols shortened, so two builds compare by function. Lines below the
report's --percent-limit are absent (0.00 here means "under the limit", not "zero").

    pdiff.py <control report-sym.txt> <candidate report-sym.txt>
"""
import re,sys
def load(p):
    ev=None; out={}
    for l in open(p):
        m=re.match(r"# Event count \(approx.\): (\d+)",l)
        if m: ev=int(m.group(1)); continue
        m=re.match(r"\s+([\d.]+)%\s+(\S+)\s+(\S+)\s+\[(.)\]\s+(.*)",l)
        if not m: continue
        pct,comm,dso,k,sym=m.groups()
        dso="gotatun" if dso.startswith("gotatun-") else dso
        comm="gotatun-crypto" if comm.startswith("gotatun-crypto") else comm
        sym=re.sub(r"Cs[0-9A-Za-z]{8,}_","",sym.strip())
        # crude Rust v0 shortening: keep identifiers longer than 4 chars
        if sym.startswith("_R"):
            ids=re.findall(r"\d+([a-z_][A-Za-z0-9_]{3,})",sym)
            sym="::".join(ids[:6])
        key=(comm,dso,sym[:110])
        out[key]=out.get(key,0)+float(pct)/100*ev
    return out,ev
a,ea=load(sys.argv[1]); b,eb=load(sys.argv[2])
print("total Gcycles", round(ea/1e9,1), round(eb/1e9,1))
keys=set(a)|set(b)
rows=sorted(keys,key=lambda k:-(b.get(k,0)-a.get(k,0)))
for k in rows[:28]:
    print("%+7.2f  %6.2f -> %6.2f  %s"%((b.get(k,0)-a.get(k,0))/1e9,a.get(k,0)/1e9,b.get(k,0)/1e9," | ".join(k)))
print("...")
for k in rows[-8:]:
    print("%+7.2f  %6.2f -> %6.2f  %s"%((b.get(k,0)-a.get(k,0))/1e9,a.get(k,0)/1e9,b.get(k,0)/1e9," | ".join(k)))
