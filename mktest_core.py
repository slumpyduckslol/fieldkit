#!/usr/bin/env python3
"""Build _test_core.html: the untouched v1 suite (test_core.js) plus a browser shim,
so the regression run does not need node."""
import pathlib

here = pathlib.Path(__file__).parent
core = (here / "SEALED-CORE.js").read_text(encoding="utf-8").replace("</script", "<\\/script")
body = (here / "test_core.js").read_text(encoding="utf-8")

marker = "let pass = 0, fail = 0;"
i = body.index(marker)
body = "const TK = window.TK;\n" + body[i:]
body = body.replace("process.exit(fail ? 1 : 0);", "").replace("</script", "<\\/script")

page = """<!doctype html><meta charset="utf-8"><title>fieldkit v1 core tests</title>
<body><pre id="corelog">did not run</pre>
<script>
%s
</script>
<script>
(function () {
  var LOG = [];
  var console = { log: function (s) { LOG.push(String(s)); } };
  var process = { exit: function () {} };
  var Buffer = { from: function (s) { return { toString: function () {
    return btoa(String(s)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } }; } };
  try {
%s
  } catch (e) { LOG.push('THREW ' + e.message + ' @ ' + (e.stack || '').split('\\n')[1]); }
  var pre = document.getElementById('corelog');
  pre.textContent = LOG.join('\\n');
})();
</script>
</body>
""" % (core, body)

out = here / "_test_core.html"
out.write_text(page, encoding="utf-8")
print("wrote", out, len(page.encode("utf-8")), "bytes")
