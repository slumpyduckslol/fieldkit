#!/usr/bin/env python3
"""Inline SEALED-CORE.js into shell.html -> index.html (one self-contained file).

Gotcha handled here: the payload crib contains the literal string </script>,
which a browser treats as the end of the inline <script> block no matter what
quotes it sits inside. Escaping the slash inside the JS string fixes it, so the
core actually loads.
"""
import pathlib, sys

here = pathlib.Path(__file__).parent
core = (here / "SEALED-CORE.js").read_text(encoding="utf-8")
shell = (here / "shell.html").read_text(encoding="utf-8")

# 1. neutralise any closing script tag hiding inside JS strings
core = core.replace("</script", "<\\/script")

marker = "/*__CORE__*/"
if marker not in shell:
    sys.exit("marker missing from shell.html")

out = shell.replace(marker, core, 1)

# 2. hard guarantee: exactly one </script> per block in the output body
if out.count("</script") > 3:
    sys.exit(f"unbalanced </script>: {out.count('</script')} occurrences")

target = here / "index.html"
target.write_text(out, encoding="utf-8")
print(f"built {target}  {len(out.encode('utf-8')):,} bytes  ({out.count('</script')} script closers)")
