# Field Kit v2 — new panels (paste this to your designer)

This ADDS panels to the field kit you already restyled. Same rules as last time:
**you design and build the markup + CSS. You do not write the logic.** The logic
lives in the SEALED CORE script block — leave it exactly as it is. A later sealed-core
update (v2) will make these panels actually compute. Until that update is merged in,
a new panel's button shows `ERR: unknown tool <name>` in the status line when tapped.
That is expected and correct — it means the wiring contract is intact and waiting.

Design language: same as v1. Dark, dense, one-handed phone use, 44px touch targets,
monospace for anything that is a command/hash/payload. Keep the CSS variables.
Do not add CDN, fonts, frameworks, or network calls of any kind — the app must stay
a single offline file.

---

## Panels to add (8)

Each is a new `<section data-tool="X">` plus a matching nav button
`<button data-tab="X">`. Tab order after the existing seven:
**CIDR, IPv6, SSRF, Redirect, Traversal, Quotes, Wordlist, Cheat Sheets.**

### 1. CIDR — `data-tool="cidr"`
Subnet math. Offline, pure arithmetic.
- inputs: `data-in="cidr"` text (placeholder `10.0.0.0/22`), `data-in="split"` text (optional, `24` = split into /24s)
- action: `data-act="calc"` (primary button "Calculate")
- outputs: `data-out="result"` (network, first/last host, broadcast, mask, wildcard, host count, split list)

### 2. IPv6 — `data-tool="ipv6"`
Expand + variant generator (SSRF filter-bypass shapes).
- input: `data-in="addr"` text (placeholder `::1` or `2001:db8::1`)
- action: `data-act="calc"` ("Expand")
- outputs: `data-out="result"` (full form, compressed forms, bracketed `[...]` form, v4-mapped `::ffff:127.0.0.1`, decimal form)
- optional second action: `data-act="variants"` ("Bypass variants")

### 3. SSRF — `data-tool="ssrf"`
The money panel. Given a host, produce every encoding that means the same IP.
- inputs: `data-in="host"` text (placeholder `127.0.0.1`), `data-in="port"` text (optional, default 80), `data-in="scheme"` select (`http` / `https` / `gopher` / `file`)
- action: `data-act="gen"` ("Generate matrix")
- outputs: `data-out="result"` (grouped list: dotted, decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, shortened `127.1`, bracketed IPv6 `[::ffff:127.0.0.1]`, `localtest.me`, `0.0.0.0` variants, DNS-rebind placeholder, cloud metadata `169.254.169.254` rows)
- keep `data-out="listener"` empty in this panel — single-output panel like v1

### 4. Redirect — `data-tool="redirect"`
Open-redirect bypass variants for one evil host.
- input: `data-in="evil"` text (placeholder `evil.example`)
- action: `data-act="gen"` ("Variants")
- output: `data-out="result"` (`//evil`, `https:evil`, `/\evil`, `\@evil`, `@evil`, `https://evil\@good`, `//evil%2f..`, `/%2f%2eevil` shapes — one per line, labeled)

### 5. Traversal — `data-tool="traversal"`
Path-traversal depth + encoding sprayer.
- inputs: `data-in="path"` text (placeholder `/etc/passwd`), `data-in="prefix"` text (optional, placeholder `?file=`)
- action: `data-act="gen"` ("Spray")
- output: `data-out="result"` (depths 1–10 plain, double-encoded `%252e`, overlong `..%c0%af`, `....//`, null-byte `%00` legacy rows)

### 6. Quotes — `data-tool="quotes"`
"What breaks this string" breaker.
- input: `data-in="str"` text (placeholder `admin'--`)
- action: `data-act="gen"` ("Break it")
- output: `data-out="result"` (single-quote, double-quote, backtick, backslash-escape, no-quote, hex-literal, char-literal variants of the input, labeled by context: SQL / shell / JS / URL)

### 7. Wordlist — `data-tool="wordmix"`
Custom password-candidate mixer. Generates; it does not crack.
- inputs: `data-in="name"` text (placeholder `acme`), `data-in="year"` text (placeholder `2026`), `data-in="extras"` text (comma-separated seasons/words, optional)
- action: `data-act="gen"` ("Mix")
- outputs: `data-out="result"` (base, Capitalized, lower, upper, `name2026`, `name!`, `name!1`, `Name!1`, leet `n4me`, season+name, name+season rows), `data-out="count"` (line count)

### 8. Cheat Sheets — `data-tool="cheat"`
Static reference, zero logic needed. This panel CAN be fully functional immediately.
- inputs: `data-in="q"` text (filter box, placeholder `sqli, redis, ssh…`)
- action: `data-act="look"` ("Search")
- output: `data-out="result"`
- content lives in the sealed core v2; design the panel to display ~40 short rows of
  `topic    command` monospace lines. Filter behavior identical to the existing
  Ports panel (empty q = show all).

---

## House rules (unchanged from v1, still load-bearing)

1. One HTML file. No CDN, no external fonts, no frameworks, no build step.
2. The SEALED CORE script block: untouched, byte-for-byte.
3. The WIRING script block: untouched. It already handles any number of panels
   generically — you add zero JavaScript.
4. Keep every `data-*` attribute exactly as named above. No renames, no deletions.
5. Keep checkboxes as `<input type="checkbox">` (nmap panel still has four).
6. Never let literal `</script>` appear inside a script block. Escape as `<\/script>`.
7. Fix the tab bar from v1: seven tabs overflowed into a scroll strip at 430px.
   With 15 tabs total you MUST use a 2-row grid or a bottom bar — thumb-reachable.

## When it comes back

Hand the file to Wraith. He merges the v2 sealed core (the logic for all eight
panels), re-seals, and runs the checker. Do not merge any core yourself.
