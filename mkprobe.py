#!/usr/bin/env python3
"""Copy index.html, inject probe.js before </body>, write probe.html (shipped file untouched)."""
import pathlib

here = pathlib.Path(__file__).parent
html = (here / "index.html").read_text(encoding="utf-8")
probe = (here / "probe.js").read_text(encoding="utf-8").replace("</script", "<\\/script")

inject = "\n<script>\n" + probe + "\n</script>\n"
if "</body>" not in html:
    raise SystemExit("no </body> in index.html")
out = html.replace("</body>", inject + "</body>", 1)
(here / "probe.html").write_text(out, encoding="utf-8")
print("wrote probe.html", len(out.encode("utf-8")), "bytes")
