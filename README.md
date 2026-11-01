# Field Kit

A single-file, offline pentest toolkit that runs in any phone browser. No install, no server, no accounts, no network calls. One HTML file, open it, use it.

Public build: **https://silly-capybara-5768bf.netlify.app**

Works on a non-rooted phone — it is just a web page.

## What's in it

Sixteen panels, all computed locally in the page:

| Panel | Does |
| --- | --- |
| Codec | base64 / URL / hex / HTML encode+decode, ROT13 |
| Hash ID | guesses hash type from length + charset |
| JWT | decodes header + payload, shows claim timings |
| Nmap | assembles a clean scan command from checkboxes |
| Shell | reverse shell one-liners (37 shapes) |
| Ports | 40 common ports with triage notes, filterable |
| Payload | crib cheatsheet — 22 payloads by context |
| CIDR | network / broadcast / mask / host range, host-bit warning, subnet split |
| IPv6 | expand + compress (RFC 5952), v4-mapped and v4-embedded forms |
| SSRF | ~33 representations of one internal address, one meaning |
| Redir | 15 open-redirect shapes for a target URL |
| Paths | 17 traversal sprays, depths 1–10, double-URL and TOCTOU variants |
| Quotes | 13 ways to break the same string literal |
| Wordmix | name + year + extras → a candidate list, not a crack |
| Cheats | 62 technique rows: white 14 / grey 9 / black 21 / common 18 |
| Dorks | 47 Google dorks in 7 categories, text + category filter |

Every generated list is a string you can copy. Nothing leaves the device — open devtools and watch: zero outbound requests.

## How it's built

The HTML is generated, not hand-edited:

```
shell.html        # markup, CSS, the tab bar, and the [data-act] wiring layer
SEALED-CORE.js    # logic only: no DOM, no CSS. defines window.TK
build.py          # inlines the core into the shell -> index.html
verify.py         # contract check on the built file
test_v2.js        # unit tests for the current core (143)
test_core.js      # original core tests (28), still green
mktest.py         # test_v2.js  -> _test.html
mktest_core.py    # test_core.js -> _test_core.html (+ console/process/Buffer shims)
```

Rebuild:

```sh
python3 build.py            # writes index.html
python3 verify.py index.html  # OK core sealed, 16 tools wired / SHIPPABLE
```

### Running the tests without node

No node required. The harness pages inline the core plus a suite, print `PASS`/`FAIL` into `<pre id="results">`, and any headless Chromium reads them:

```sh
python3 mktest.py && python3 mktest_core.py
brave-browser --headless=new --disable-gpu --dump-dom file://$PWD/_test.html      | grep -c PASS
brave-browser --headless=new --disable-gpu --dump-dom file://$PWD/_test_core.html | grep -c PASS
```

Current: 143/143 and 28/28.

### The contract

The core and the UI only talk through one function:

```js
window.TK.run(tool, act, vals) // -> { out: { key: string }, note: string }
```

The wiring layer finds every `[data-act]` inside `section[data-tool=X]`, reads the inputs marked `[data-in]`, calls `TK.run`, and writes results into `[data-out]`.

`verify.py` holds a `CONTRACT` dict of `(inputs, acts, outputs)` per panel and fails the build if any panel drifts from it, so a redesign can't silently drop a tool.

That means **you can replace shell.html entirely** — new CSS, new layout, new framework — and the tools keep working as long as the attributes and the `TK.run` shape stay the same.

### Gotcha worth knowing

The payload crib contains the literal string `</script>`. Inlined into `<script>`, a browser closes the block right there and the whole app dies with `window.TK === undefined`. `build.py` escapes it to `<\/script>` and hard-fails if the built file has more than 3 script closers. `verify.py` catches it if anyone forgets.

Run `verify.py` on any redesign before deploying.

## Deploy

Netlify drop: drag the built file onto the existing project to keep the URL, or link the repo once (Site settings → Build & deploy → Link repository, publish dir `.`, build command blank) and every push auto-deploys.

## Layout

The tab bar is a 3-row grid — 6 / 6 / 4 — at ≥384px, and 4 columns below that. Every tab is 44px tall with no clipped labels; `_probe.js` measures both in a real browser after any restyle.

## Scope

This is a helper for authorized work — your own labs, your own gear, engagements you're cleared for. The tools generate commands, decode data and list payload shapes; they don't attack anything by themselves. SSL Labs-style per-target tools and anything that phones home were left out on purpose.

## License

MIT
