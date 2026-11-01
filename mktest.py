#!/usr/bin/env python3
"""Build _test.html: sealed core + test_v2.js, runnable under `brave-browser --headless --dump-dom`.
No node on this box, so the browser is the test runner."""
import pathlib

here = pathlib.Path(__file__).parent
core = (here / "SEALED-CORE.js").read_text(encoding="utf-8").replace("</script", "<\\/script")
tests = (here / "test_v2.js").read_text(encoding="utf-8").replace("</script", "<\\/script")

page = """<!doctype html><meta charset="utf-8"><title>fieldkit tests</title>
<body><pre id="results">did not run</pre>
<script>
%s
</script>
<script>
%s
</script>
</body>
""" % (core, tests)

out = here / "_test.html"
out.write_text(page, encoding="utf-8")
print("wrote", out, len(page.encode("utf-8")), "bytes")
