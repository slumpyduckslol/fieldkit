/* injected into a COPY of index.html to prove the wiring + the tab bar in a real browser */
(function () {
  'use strict';
  var out = [];
  var nav = document.getElementById('tabs');
  var btns = [].slice.call(nav.querySelectorAll('button'));
  out.push('tabs=' + btns.length);
  out.push('docW=' + document.documentElement.scrollWidth + ' winW=' + window.innerWidth);
  var rows = {};
  btns.forEach(function (b) {
    var r = b.getBoundingClientRect();
    var k = Math.round(r.top);
    (rows[k] = rows[k] || []).push(b);
  });
  var tops = Object.keys(rows).map(Number).sort(function (a, b) { return a - b; });
  out.push('rows=' + tops.length);
  tops.forEach(function (t, i) {
    var bs = rows[t];
    var h = Math.round(bs[0].getBoundingClientRect().height);
    var clip = bs.filter(function (b) { return b.scrollWidth > b.clientWidth + 1; });
    out.push('row' + (i + 1) + ' n=' + bs.length + ' h=' + h +
      ' clip=' + clip.length +
      ' [' + bs.map(function (b) { return b.textContent; }).join(' ') + ']');
  });
  var vh = [];
  btns.forEach(function (b) { if (b.getBoundingClientRect().height < 43.5) vh.push(b.textContent); });
  out.push('under44=' + vh.length);

  /* tab switching */
  var switchFails = [];
  btns.forEach(function (b) {
    b.click();
    var sec = document.querySelector('section[data-tool="' + b.dataset.tab + '"]');
    var on = document.querySelectorAll('section[data-tool].on');
    if (!sec || !sec.classList.contains('on') || on.length !== 1) switchFails.push(b.dataset.tab);
  });
  out.push('switchFails=' + (switchFails.join(',') || 'none'));

  /* live wiring, every panel */
  var jwt = btoa(JSON.stringify({ alg: 'HS256' })).replace(/=+$/, '') + '.' +
            btoa(JSON.stringify({ sub: '7', exp: 1900000000 })).replace(/=+$/, '') + '.x';
  var plan = {
    codec:     { in: { input: 'hello' }, act: 'b64enc' },
    hashid:    { in: { hash: 'd41d8cd98f00b204e9800998ecf8427e' }, act: 'id' },
    jwt:       { in: { token: jwt }, act: 'decode' },
    nmap:      { in: { target: '10.0.0.5', ports: '22,80' }, act: 'build' },
    rev:       { in: { ip: '10.0.0.1', port: '4444', shell: 'bash' }, act: 'gen', extra: 'listener' },
    ports:     { in: { q: 'redis' }, act: 'look' },
    crib:      { in: { q: 'xss' }, act: 'look' },
    cidr:      { in: { cidr: '10.0.0.0/22', split: '24' }, act: 'calc' },
    ipv6:      { in: { addr: '::ffff:127.0.0.1' }, act: 'calc' },
    ssrf:      { in: { host: '127.0.0.1', port: '80', scheme: 'http' }, act: 'gen' },
    redirect:  { in: { evil: 'evil.example' }, act: 'gen' },
    traversal: { in: { path: '/etc/passwd', prefix: '?file=' }, act: 'gen' },
    quotes:    { in: { str: "admin'--" }, act: 'gen' },
    wordmix:   { in: { name: 'acme', year: '2026' }, act: 'gen', extra: 'count' },
    cheat:     { in: { q: 'redis' }, act: 'look' },
    dorks:     { in: { q: '', cat: 'cloud' }, act: 'look' }
  };
  Object.keys(plan).forEach(function (tool) {
    var sec = document.querySelector('section[data-tool="' + tool + '"]');
    if (!sec) { out.push('WIRE ' + tool + ' MISSING SECTION'); return; }
    Object.keys(plan[tool].in).forEach(function (k) {
      var el = sec.querySelector('[data-in="' + k + '"]');
      if (!el) { out.push('WIRE ' + tool + ' MISSING IN ' + k); return; }
      el.value = plan[tool].in[k];
    });
    var btn = sec.querySelector('[data-act="' + plan[tool].act + '"]');
    if (!btn) { out.push('WIRE ' + tool + ' MISSING ACT'); return; }
    btn.click();
    var res = sec.querySelector('[data-out="result"]');
    var note = sec.querySelector('[data-note]');
    var n = res ? res.textContent.length : -1;
    var noteTxt = note ? note.textContent : '';
    var bad = (n <= 0) || /^ERR:/.test(noteTxt);
    var extra = '';
    if (plan[tool].extra) {
      var ex = sec.querySelector('[data-out="' + plan[tool].extra + '"]');
      extra = ' ' + plan[tool].extra + '=' + (ex ? JSON.stringify(ex.textContent) : 'MISSING');
    }
    out.push('WIRE ' + tool + (bad ? ' FAIL' : ' ok') + ' chars=' + n + extra +
      ' note=' + JSON.stringify(noteTxt.slice(0, 70)));
  });

  /* label fit for phone widths the desktop window cannot emulate */
  function fitAt(W) {
    var cols = (W <= 383) ? 4 : 6;
    var gap = 5, pad = 24, chrome = 6; /* 2 border + 2*2 padding */
    var cell = (W - pad - gap * (cols - 1)) / cols;
    var avail = cell - chrome;
    var cv = document.createElement('canvas').getContext('2d');
    var cs = getComputedStyle(btns[0]);
    cv.font = cs.fontStyle + ' ' + cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily;
    var ls = parseFloat(cs.letterSpacing) || 0;
    var worst = { t: '', w: 0 }, bad = [];
    btns.forEach(function (b) {
      var t = b.textContent;
      var w = cv.measureText(t).width + ls * t.length;
      if (w > avail) bad.push(t + ' ' + w.toFixed(1) + '>' + avail.toFixed(1));
      if (w > worst.w) worst = { t: t, w: w };
    });
    return 'fit' + W + ' cols=' + cols + ' avail=' + avail.toFixed(1) +
      ' worst=' + worst.t + ' ' + worst.w.toFixed(1) + ' margin=' + (avail - worst.w).toFixed(1) +
      ' clip=' + (bad.length ? bad.join(' , ') : 'none');
  }
  [430, 412, 390, 384, 375, 360, 320].forEach(function (W) { out.push(fitAt(W)); });

  var pre = document.createElement('pre');
  pre.id = 'probe';
  pre.textContent = out.join('\n');
  document.body.appendChild(pre);
})();
