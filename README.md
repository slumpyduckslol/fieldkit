# Field Kit

A single-file, offline pentest toolkit that runs in any phone browser. No install, no server, no accounts, no network calls. One HTML file, open it, use it.

Public build: **https://silly-capybara-5768bf.netlify.app**

Works on a non-rooted phone — it is just a web page.

## What's in it

Seven tabs, all computed locally in the page:

| Tab | Does |
| --- | --- |
| Codec | base64 / URL / hex / HTML encode+decode, ROT13 |
| Hash ID | guesses hash type from length + charset |
| JWT | decodes header + payload, shows claim timings |
| Nmap | assembles a clean scan command from checkboxes |
| Revshell | generates reverse shell one-liners |
| Ports | explains common ports / quick triage notes |
| Crib | payload cheatsheet |

Nothing leaves the device. Open devtools: zero outbound requests.

## How it's built

The HTML is generated, not hand-edited:

```
shell.html        # markup, CSS, and the [data-act] wiring layer
SEALED-CORE.js    # logic only: no DOM, no CSS. defines window.TK
build.py          # inlines the core into the shell -> index.html
verify.py         # contract check on the built file
test_core.js      # unit tests for the core
```

Rebuild:

```sh
python3 build.py     # writes index.html
python3 verify.py    # OK — contract holds.
node test_core.js    # 28/28
```

### The contract

The core and the UI only talk through one function:

```js
window.TK.run(tool, act, vals) // -> { out: { key: string }, note: string }
```

The wiring layer finds every `[data-act]` inside `section[data-tool=X]`, reads the inputs marked `[data-in]`, calls `TK.run`, and writes results into `[data-out]`.

That means **you can replace shell.html entirely** — new CSS, new layout, new framework — and the tools keep working as long as the attributes and the `TK.run` shape stay the same.

### Gotcha worth knowing

The payload crib contains the literal string `</script>`. Inlined into `<script>`, a browser closes the block right there and the whole app dies with `window.TK === undefined`. `build.py` escapes it to `<\/script>` and hard-fails if the built file has more than 2 script closers. `verify.py` catches it if anyone forgets.

Run `verify.py` on any redesign before deploying.

## Scope

This is a helper for authorized work — your own labs, your own gear, engagements you're cleared for. The tools generate commands and decode data; they don't attack anything by themselves.

## License

MIT
