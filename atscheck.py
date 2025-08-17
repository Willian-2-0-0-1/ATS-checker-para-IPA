#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
atscheck — App Transport Security (ATS) checker for any .ipa
- Descobre TODAS as Info.plist em Payload/** (inclui .appex)
- Lista exceções por domínio:
  * NSExceptionAllowsInsecureHTTPLoads (e a variante legacy NSTemporary*)
  * NSIncludesSubdomains
  * NSRequiresCertificateTransparency
  * TLS mínimo / Forward Secrecy
- Saída colorida (ANSI) SEMPRE por padrão
- Suporta --json, --domain, e exit codes úteis para CI:
    0 = OK (sem HTTP efetivo permitido)
    2 = HTTP efetivo permitido encontrado
    3 = erro de uso/arquivo

Uso:
  python3 atscheck.py app.ipa
  python3 atscheck.py app.ipa --json
  python3 atscheck.py app.ipa --domain exemplo.com
  python3 atscheck.py app.ipa --color auto|always|never
"""
import argparse, fnmatch, json, os, sys, zipfile, plistlib
from typing import Dict, Any, List

# ===== ANSI =====
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
CYAN  = "\033[36m"; YEL  = "\033[33m"; GRN = "\033[32m"
RED   = "\033[31m"; BLU  = "\033[34m"

def wants_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    # auto
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")

def c_bool(v, use_color: bool):
    if v is True:  return f"{GRN}True{RESET}" if use_color else "True"
    if v is False: return f"{RED}False{RESET}" if use_color else "False"
    return f"{DIM}None{RESET}" if use_color else "None"

def c_txt(s: str, col: str, use_color: bool):
    return f"{col}{s}{RESET}" if use_color else str(s)

def K(s: str, use_color: bool):   return c_txt(s, BLU, use_color)
def H(s: str, use_color: bool):   return c_txt(s, CYAN + BOLD, use_color)
def DOM(s: str, use_color: bool): return c_txt(s, YEL + BOLD, use_color)

# ===== keys =====
ATS_TOP_KEYS = [
    "NSAllowsArbitraryLoads",
    "NSAllowsArbitraryLoadsInWebContent",
    "NSAllowsArbitraryLoadsForMedia",
]
DOMAIN_KEYS = [
    "NSExceptionAllowsInsecureHTTPLoads",
    "NSTemporaryExceptionAllowsInsecureHTTPLoads",   # legacy
    "NSIncludesSubdomains",
    "NSRequiresCertificateTransparency",
    "NSExceptionMinimumTLSVersion",
    "NSTemporaryExceptionMinimumTLSVersion",         # legacy
    "NSExceptionRequiresForwardSecrecy",
    "NSTemporaryExceptionRequiresForwardSecrecy",    # legacy
]

def find_all_info_plists(z: zipfile.ZipFile) -> List[str]:
    pats = [
        "Payload/*.app/Info.plist",
        "Payload/**/*.app/Info.plist",
        "Payload/**/*.appex/Info.plist",
    ]
    out = [name for name in z.namelist() if any(fnmatch.fnmatch(name, p) for p in pats)]
    seen = set(); ordered = []
    for p in out:
        if p not in seen:
            ordered.append(p); seen.add(p)
    return ordered

def parse_plist(z: zipfile.ZipFile, path: str) -> Dict[str, Any]:
    return plistlib.loads(z.read(path))

def summarize_pl(pl: Dict[str, Any]) -> Dict[str, Any]:
    ats = pl.get("NSAppTransportSecurity", {}) or {}
    exc = ats.get("NSExceptionDomains", {}) or {}
    top = {k: ats.get(k) for k in ATS_TOP_KEYS}
    domains = []
    for dname, cfg in sorted(exc.items()):
        row = {"domain": dname}
        for k_ in DOMAIN_KEYS:
            row[k_] = cfg.get(k_)
        http_domain = bool(row["NSExceptionAllowsInsecureHTTPLoads"]) or bool(row["NSTemporaryExceptionAllowsInsecureHTTPLoads"])
        http_global = bool(top.get("NSAllowsArbitraryLoads"))
        row["effective_http_permitted"] = bool(http_domain or http_global)
        row["MinimumTLSVersionEffective"] = row["NSExceptionMinimumTLSVersion"] or row["NSTemporaryExceptionMinimumTLSVersion"]
        domains.append(row)
    return {"top_level": top, "domains": domains}

def run(ipa_path: str, filter_domain: str, json_mode: bool, color_mode: str) -> int:
    try:
        with zipfile.ZipFile(ipa_path) as z:
            plist_paths = find_all_info_plists(z)
            if not plist_paths:
                print("Info.plist not found in IPA.", file=sys.stderr)
                return 3
            results = []
            for p in plist_paths:
                try:
                    pl = parse_plist(z, p)
                except Exception as e:
                    print(f"Warning: Could not parse {p}: {e}", file=sys.stderr)
                    continue
                summary = summarize_pl(pl)
                results.append({"info_plist": p, **summary})
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        print(f"Error opening IPA: {e}", file=sys.stderr)
        return 3

    if filter_domain:
        for r in results:
            r["domains"] = [d for d in r["domains"] if d["domain"] == filter_domain]

    insecure = any(d["effective_http_permitted"] for r in results for d in r["domains"])

    if json_mode:
        print(json.dumps({"ipa": os.path.basename(ipa_path), "results": results}, indent=2, sort_keys=True))
        return 2 if insecure else 0

    use_color = wants_color(color_mode)
    print(H(f"IPA: {ipa_path}", use_color))
    for r in results:
        print(H(f"Info.plist: {r['info_plist']}", use_color))
        print(H("=== Top-level ATS ===", use_color))
        for kname, val in r["top_level"].items():
            print(f"  - {K(kname, use_color)}: {c_bool(val, use_color)}")
        print()
        if not r["domains"]:
            print("  (No NSExceptionDomains or filtered by --domain)\n")
            continue
        print(H("=== Domain exceptions ===", use_color))
        for d in r["domains"]:
            print(f"[{DOM(d['domain'], use_color)}]")
            print(f"  - {K('NSExceptionAllowsInsecureHTTPLoads', use_color)}: {c_bool(d['NSExceptionAllowsInsecureHTTPLoads'], use_color)}")
            print(f"  - {K('NSTemporaryExceptionAllowsInsecureHTTPLoads', use_color)}: {c_bool(d['NSTemporaryExceptionAllowsInsecureHTTPLoads'], use_color)}")
            print(f"  - {K('NSIncludesSubdomains', use_color)}: {c_bool(d['NSIncludesSubdomains'], use_color)}")
            print(f"  - {K('NSRequiresCertificateTransparency', use_color)}: {c_bool(d['NSRequiresCertificateTransparency'], use_color)}")
            mtls = d['MinimumTLSVersionEffective']
            mtls_str = mtls if mtls else "None"
            mtls_fmt = c_txt(mtls_str, GRN, use_color) if mtls else (f"{DIM}{mtls_str}{RESET}" if use_color else mtls_str)
            print(f"  - {K('MinimumTLSVersion (Exception/Temporary)', use_color)}: {mtls_fmt}")
            eff = d['effective_http_permitted']
            eff_fmt = c_txt("True", GRN, use_color) if eff else c_txt("False", RED, use_color)
            print(f"  - {K('Effective HTTP permitted', use_color)}: {eff_fmt}")
            print()

    return 2 if insecure else 0

def main():
    ap = argparse.ArgumentParser(description="Check ATS exceptions inside an iOS .ipa (Info.plist).")
    ap.add_argument("ipa", help="Path to .ipa file")
    ap.add_argument("--json", action="store_true", help="Print JSON output")
    ap.add_argument("--domain", help="Filter by specific domain (e.g., api.example.com)")
    ap.add_argument("--color", choices=["always","auto","never"], default="always",
                    help="Color mode (default: always)")
    args = ap.parse_args()
    rc = run(args.ipa, filter_domain=args.domain, json_mode=args.json, color_mode=args.color)
    sys.exit(rc)

if __name__ == "__main__":
    main()
