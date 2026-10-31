# Field Kit — design handoff

Paste everything under **THE PROMPT** into your AI builder. Attach `index.html` as the reference.
When it comes back, hand me the file and I re-seal it. You should never have to explain
the contract yourself — it's below in their words.

---

## THE PROMPT (copy from here)

> Restyle this single-page mobile web app. It is a self-contained pentest field kit that
> runs from a local file with no internet, so: **one HTML file, no CDN, no external fonts,
> no frameworks, no build step, no imports.** Everything inline.
>
> **You are doing design only. Do not rewrite the JavaScript logic.**
>
> ### The rule that matters
> There are two `<script>` blocks. The first one is marked
> `SEALED CORE` and must be copied through **byte for byte, untouched**. The second
> block is `WIRING` and must also stay intact. You may freely rewrite the `<style>` block
> and re-order or re-style the markup — but every `data-*` attribute listed below must
> survive exactly, because the wiring finds elements by those attributes, not by class
> names.
>
> ### Structure contract — keep all of these
> | Attribute | Where | Meaning |
> |---|---|---|
> | `data-tool="X"` | on each `<section>` | tool id: `codec`, `hashid`, `jwt`, `nmap`, `rev`, `ports`, `crib` |
> | `class="on"` | one section + its tab | the currently visible panel |
> | `data-tab="X"` | on each nav button | switches to section `data-tool="X"` |
> | `data-in="name"` | on every input/select/textarea | the value handed to the logic |
> | `data-act="name"` | on every action button | which function to call |
> | `data-out="key"` | on every `<pre>` | where the result is written |
> | `data-copy="key"` | on copy buttons | copies the matching `data-out` |
> | `data-note` | on the small `<p>` | status line under the output |
>
> You may add classes, wrappers, icons, cards, gradients, animation — anything visual.
> You may **not**: rename `data-*` values, delete a `data-in`/`data-act`/`data-out`, change
> `<pre>` to another element, or add a second element with the same `data-out` key inside
> one section.
>
> ### The input/output names already in use — preserve these pairs
> - **codec** — in `input` → out `result`; acts: `b64enc b64dec urlenc urldec hexenc hexdec htmlenc html_dec rot13`
> - **hashid** — in `hash` → out `result`; act: `id`
> - **jwt** — in `token` → out `result`; act: `decode`
> - **nmap** — in `target scantype timing ports svc scripts pn aggr out` → out `result`; act: `build`
>   (`svc/scripts/pn/aggr` are checkboxes — keep them as `<input type="checkbox">`)
> - **rev** — in `ip port shell` → out `listener` **and** `result`; act: `gen`
> - **ports** — in `q` → out `result`; act: `look`
> - **crib** — in `q` → out `result`; act: `look`
>
> ### Design direction
> Dark, dense, instrument-panel feel — this is used one-handed on a phone in a dark room.
> Big touch targets (min 44px tall). Monospace for anything that is a command or a hash.
> The colour variables at the top of the CSS are the theme: `--bg --panel --line --txt
> --dim --accent --warn --err`. Keep them as variables so the theme stays swappable.
> Status line has three states already wired: `.note` (normal), `.note.err` (red),
> `.note.warn` (amber) — style all three.
> Layout target: 390–430px wide first, then a comfortable desktop fallback.
>
> ### One trap to avoid
> Never let the literal text `</script>` appear inside a `<script>` block — it ends the
> block early and the whole app dies silently with a blank output. If you add any sample
> payload text, escape it as `<\/script>`.

---

## What comes back to me

A single `.html` file. I check three things:

1. `window.TK.run` still exists and every `data-*` pair above is present (I diff the
   attribute map automatically).
2. The sealed core is unchanged (byte compare against `SEALED-CORE.js`).
3. Two live clicks: an encode and an nmap build still produce output.

Then it's sealed and it's done. Nothing to rebuild.

## Files here

| File | What it is | Who touches it |
|---|---|---|
| `SEALED-CORE.js` | all the logic, zero DOM | me only |
| `shell.html` | reference markup + wiring + CSS | your restyle replaces the look |
| `build.py` | inlines core into one file | me only |
| `index.html` | **the shipped artifact** — open this one | nobody |
| `test_core.js` | 28 assertions on the logic | me only |

Rebuild after any edit: `python3 build.py` → new `index.html`.
