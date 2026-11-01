#!/usr/bin/env python3
"""Verify any redesign (yours or a designer's) against the fieldkit contract.

    python3 verify.py newdesign.html

Exits 0 = safe to ship. Exits 1 = something downstream will break, with the reason.
"""
import pathlib, re, sys, html as htmllib

HERE = pathlib.Path(__file__).parent

# section -> (required data-in names, required data-act names, required data-out names)
CONTRACT = {
    "codec":  (["input"],
               ["b64enc", "b64dec", "urlenc", "urldec", "hexenc", "hexdec", "htmlenc", "html_dec", "rot13"],
               ["result"]),
    "hashid": (["hash"], ["id"], ["result"]),
    "jwt":    (["token"], ["decode"], ["result"]),
    "nmap":   (["target", "scantype", "timing", "ports", "svc", "scripts", "pn", "aggr", "out"],
               ["build"], ["result"]),
    "rev":    (["ip", "port", "shell"], ["gen"], ["listener", "result"]),
    "ports":  (["q"], ["look"], ["result"]),
    "crib":   (["q"], ["look"], ["result"]),
    "cidr":   (["cidr", "split"], ["calc"], ["result"]),
    "ipv6":   (["addr"], ["calc", "variants"], ["result"]),
    "ssrf":   (["host", "port", "scheme"], ["gen"], ["result"]),
    "redirect": (["evil"], ["gen"], ["result"]),
    "traversal": (["path", "prefix"], ["gen"], ["result"]),
    "quotes": (["str"], ["gen"], ["result"]),
    "wordmix": (["name", "year", "extras"], ["gen"], ["result", "count"]),
    "cheat":  (["q"], ["look"], ["result"]),
    "dorks":  (["q", "cat"], ["look"], ["result"]),
}

def attrs(fragment, name):
    return re.findall(r'data-%s\s*=\s*["\']([^"\']+)["\']' % name, fragment)

def main(path):
    src = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    fails, warns = [], []

    # ---- 1. sealed core byte-identical -------------------------------------
    core = (HERE / "SEALED-CORE.js").read_text(encoding="utf-8").replace("</script", "<\\/script")
    if "SEALED CORE" not in src:
        fails.append("the 'SEALED CORE' block is missing entirely")
    elif core.strip() not in src:
        mism = [l for l in core.splitlines() if l.strip() and l.strip() not in src]
        fails.append("sealed core was modified — %d/%d lines changed or reflowed; first: %r"
                     % (len(mism), len(core.splitlines()), mism[0][:70] if mism else "?"))

    # ---- 2. script-tag balance (the silent killer) --------------------------
    if "SEALED CORE" in src and core.count("<\\/script") != src.count("<\\/script"):
        warns.append("escaped </script> count changed — check no literal </script> crept in")

    # ---- 3. per-section attribute contract --------------------------------
    sections = {}
    for m in re.finditer(r'<section[^>]*data-tool\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</section>',
                         src, re.S | re.I):
        sections[m.group(1)] = m.group(2)

    for tool, (ins, acts, outs) in CONTRACT.items():
        body = sections.get(tool)
        if body is None:
            fails.append(f"[{tool}] section missing (no <section data-tool=\"{tool}\">)")
            continue
        got_in = set(attrs(body, "in"))
        got_act = set(attrs(body, "act"))
        got_out = set(attrs(body, "out"))
        for missing in sorted(set(ins) - got_in):
            fails.append(f"[{tool}] missing data-in=\"{missing}\"")
        for missing in sorted(set(acts) - got_act):
            fails.append(f"[{tool}] missing data-act=\"{missing}\"")
        for missing in sorted(set(outs) - got_out):
            fails.append(f"[{tool}] missing data-out=\"{missing}\"")
        # outputs must stay <pre>-like, and be unique per section
        for key in outs:
            n = len(re.findall(r'data-out\s*=\s*["\']%s["\']' % re.escape(key), body))
            if n > 1:
                fails.append(f"[{tool}] data-out=\"{key}\" appears {n}x — the wiring writes only the first")
            tag = re.search(r'<(\w+)[^>]*data-out\s*=\s*["\']%s["\']' % re.escape(key), body)
            if tag and not tag.group(1).lower() in ("pre", "code", "textarea", "output", "div", "p"):
                warns.append(f"[{tool}] data-out=\"{key}\" is a <{tag.group(1)}> — works, but <pre> is safer")

    # checkboxes must stay checkboxes
    if "nmap" in sections:
        for k in ("svc", "scripts", "pn", "aggr"):
            m = re.search(r'<input[^>]*type\s*=\s*["\']checkbox["\'][^>]*data-in\s*=\s*["\']%s["\']' % k,
                          sections["nmap"]) or \
                re.search(r'<input[^>]*data-in\s*=\s*["\']%s["\'][^>]*type\s*=\s*["\']checkbox["\']' % k,
                          sections["nmap"])
            if not m:
                fails.append(f"[nmap] data-in=\"{k}\" is no longer <input type=\"checkbox\">")

    # ---- 4. tabs still wired ---------------------------------------------
    tabs = set(attrs(src, "tab"))
    for tool in CONTRACT:
        if tool not in tabs:
            fails.append(f"no tab with data-tab=\"{tool}\" — panel unreachable")

    # ---- 5. no network deps (offline promise) ----------------------------
    for pat, why in [(r'<script[^>]+src\s*=', 'external <script src>'),
                     (r'<link[^>]+href\s*=\s*["\']https?:', 'remote stylesheet'),
                     (r'@import\s+url\(\s*["\']?https?:', 'remote @import'),
                     (r'https?://(?:fonts|cdn|unpkg|jsdelivr)', 'CDN reference')]:
        if re.search(pat, src, re.I):
            fails.append(f"breaks offline use: {why}")

    # ---- report ----------------------------------------------------------
    print(f"checking {path}  ({len(src):,} bytes)\n")
    for w in warns:
        print("  WARN  " + w)
    for f in fails:
        print("  FAIL  " + f)
    if not fails:
        print(f"  OK    core sealed, {len(CONTRACT)} tools wired, offline-safe")
        print("\nverdict: SHIPPABLE")
        return 0
    print(f"\nverdict: {len(fails)} blocking issue(s) — ship it anyway and the outputs go blank")
    return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 verify.py <file.html>")
    sys.exit(main(sys.argv[1]))
