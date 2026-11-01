/* fieldkit v2 — core behaviour suite. Runs in any browser (see _mktest.py / headless run). */
(function () {
  'use strict';
  var R = [];
  function push(line) { R.push(line); }
  function ok(name, cond, msg) { push((cond ? 'PASS ' : 'FAIL ') + name + (cond ? '' : ' :: ' + (msg || ''))); }
  function eq(name, got, want) {
    ok(name, String(got) === String(want),
      'got ' + JSON.stringify(String(got)) + ' want ' + JSON.stringify(String(want)));
  }
  function has(name, got, sub) {
    ok(name, String(got).indexOf(sub) >= 0,
      'missing ' + JSON.stringify(sub) + ' in ' + JSON.stringify(String(got).slice(0, 200)));
  }
  function nohas(name, got, sub) {
    ok(name, String(got).indexOf(sub) < 0, 'unexpected ' + JSON.stringify(sub));
  }
  function lines(s) { return String(s).split('\n').length; }
  function run(tool, act, vals) { return TK.run(tool, act, vals || {}); }
  function I() { return TK._internals; }

  var t = I();

  /* ---- 1. codec (v1, must not regress) ---- */
  (function () {
    var r = run('codec', 'b64enc', { input: 'hello' });
    eq('codec b64enc', r.out.result, 'aGVsbG8=');
    eq('codec b64dec', run('codec', 'b64dec', { input: 'aGVsbG8=' }).out.result, 'hello');
    eq('codec hexenc', run('codec', 'hexenc', { input: 'AB' }).out.result, '4142');
    eq('codec rot13', run('codec', 'rot13', { input: 'uryyb' }).out.result, 'hello');
    eq('codec urlenc', run('codec', 'urlenc', { input: 'a b' }).out.result, 'a%20b');
    has('codec empty is an err', run('codec', 'b64enc', { input: '  ' }).note, 'ERR:');
  })();

  /* ---- 2. hashid ---- */
  (function () {
    has('hashid bcrypt', run('hashid', 'id', { hash: '$2b$12$abcdefghijklmnopqrstuv' }).out.result, 'bcrypt');
    has('hashid sha512crypt', run('hashid', 'id', { hash: '$6$rounds=5000$abc$xyz' }).out.result, 'sha512crypt');
    has('hashid 32-hex', run('hashid', 'id', { hash: 'd41d8cd98f00b204e9800998ecf8427e' }).out.result, 'MD5');
    has('hashid 64-hex', run('hashid', 'id', { hash: new Array(65).join('a') }).out.result, 'SHA-256');
    has('hashid junk', run('hashid', 'id', { hash: 'not-a-hash' }).out.result, 'not a recognised hash');
  })();

  /* ---- 3. jwt ---- */
  (function () {
    function b64u(o) {
      return btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    var tok = b64u({ alg: 'HS256', typ: 'JWT' }) + '.' +
              b64u({ sub: '1', iat: 1600000000, exp: 1900000000 }) + '.sig';
    var out = run('jwt', 'decode', { token: tok }).out.result;
    has('jwt header', out, '"alg": "HS256"');
    has('jwt payload', out, '"sub": "1"');
    has('jwt exp line', out, 'exp  ');
    has('jwt not verified', out, 'signature NOT verified');
    has('jwt unsigned', run('jwt', 'decode', { token: b64u({ alg: 'none' }) + '.' + b64u({ a: 1 }) }).out.result,
      'ABSENT (unsigned)');
    has('jwt garbage is an err', run('jwt', 'decode', { token: 'nope' }).note, 'ERR:');
  })();

  /* ---- 4. nmap ---- */
  (function () {
    var r = run('nmap', 'build', { target: '10.0.0.5', scantype: 'connect', timing: '4' });
    has('nmap connect', r.out.result, '-sT');
    has('nmap top ports', r.out.result, '--top-ports 1000');
    has('nmap target last', r.out.result, '10.0.0.5');
    has('nmap syn warns', run('nmap', 'build', { target: 't', scantype: 'syn' }).note, 'root');
    has('nmap ports', run('nmap', 'build', { target: 't', ports: '22, 80' }).out.result, '-p 22,80');
    has('nmap -oN', run('nmap', 'build', { target: 't', out: 's.txt' }).out.result, '-oN s.txt');
    has('nmap no target err', run('nmap', 'build', {}).note, 'ERR:');
  })();

  /* ---- 5. revshell ---- */
  (function () {
    var r = run('rev', 'gen', { ip: '10.0.0.1', port: '4444', shell: 'bash' });
    has('rev bash', r.out.result, '10.0.0.1/4444');
    eq('rev listener', r.out.listener, 'nc -lvnp 4444');
    has('rev default', run('rev', 'gen', { ip: '1.2.3.4', port: '4444' }).out.result, 'mkfifo');
    has('rev needs port', run('rev', 'gen', { ip: '1.2.3.4' }).note, 'ERR:');
  })();

  /* ---- 6. reference lists ---- */
  (function () {
    var all = run('ports', 'look', {});
    eq('ports all', lines(all.out.result), 40);
    has('ports note', all.note, '40 of 40');
    eq('ports redis', lines(run('ports', 'look', { q: 'redis' }).out.result), 1);
    has('ports none', run('ports', 'look', { q: 'zzz' }).out.result, '(nothing matched)');
    eq('crib xss rows', lines(run('crib', 'look', { q: 'xss' }).out.result), 4);
    has('crib empty', run('crib', 'look', {}).out.result, 'ssrf');
  })();

  /* ---- 7. cidr ---- */
  (function () {
    var r = run('cidr', 'calc', { cidr: '10.0.0.0/22' });
    var o = r.out.result;
    has('cidr network', o, '10.0.0.0/22');
    has('cidr broadcast', o, '10.0.3.255');
    has('cidr mask', o, '255.255.252.0');
    has('cidr wildcard', o, '0.0.3.255');
    has('cidr first', o, '10.0.0.1');
    has('cidr last', o, '10.0.3.254');
    has('cidr hosts', o, '1,022');
    has('cidr note', r.note, '10.0.0.0/22');

    has('cidr host bits', run('cidr', 'calc', { cidr: '10.0.0.5/24' }).out.result, '! input host bits set');
    has('cidr /32 hosts 1', run('cidr', 'calc', { cidr: '10.0.0.5/32' }).out.result, 'hosts       1');
    has('cidr /31 hosts 2', run('cidr', 'calc', { cidr: '10.0.0.4/31' }).out.result, 'hosts       2');
    has('cidr metadata', run('cidr', 'calc', { cidr: '169.254.169.254/32' }).out.result, 'CLOUD METADATA');

    var s = run('cidr', 'calc', { cidr: '192.168.1.0/24', split: '26' });
    has('cidr split header', s.out.result, '4 x /26');
    has('cidr split list', s.out.result, '192.168.1.192/26');
    has('cidr split count', s.out.result, '192.168.1.0/26');
    has('cidr split note', s.note, 'split into 4 x /26');

    has('cidr bad prefix', run('cidr', 'calc', { cidr: '10.0.0.0/33' }).note, 'ERR:');
    has('cidr bad split', run('cidr', 'calc', { cidr: '10.0.0.0/24', split: '20' }).note, 'ERR:');
    has('cidr empty', run('cidr', 'calc', {}).note, 'ERR:');
  })();

  /* ---- 8. ipv6 ---- */
  (function () {
    var r = run('ipv6', 'calc', { addr: '::1' }).out.result;
    has('v6 expanded', r, '0000:0000:0000:0000:0000:0000:0000:0001');
    has('v6 compressed', r, 'compressed  ::1');
    has('v6 decimal', r, '1');
    has('v6 url host', r, '[::1]');
    has('v6 loopback note', r, 'loopback');

    var d = run('ipv6', 'calc', { addr: '2001:0db8:0000:0000:0000:0000:0000:0001' }).out.result;
    has('v6 compress long', d, '2001:db8::1');

    var m = run('ipv6', 'calc', { addr: '::ffff:127.0.0.1' }).out.result;
    has('v6 v4-mapped', m, '[::ffff:127.0.0.1]');
    has('v6 mapped note', m, 'v4-mapped');

    var v = run('ipv6', 'variants', { addr: '::1' }).out.result;
    has('v6 var zone', v, '[::1%25]');
    has('v6 var mapped hex', run('ipv6', 'variants', { addr: '::ffff:127.0.0.1' }).out.result, '::ffff:7f00:1');
    eq('v6 var rows', lines(v), 12);

    has('v6 bad', run('ipv6', 'calc', { addr: '1::2::3' }).note, 'ERR:');
    has('v6 group overflow', run('ipv6', 'calc', { addr: '12345::1' }).note, 'ERR:');
  })();

  /* ---- 9. loose v4 + ssrf ---- */
  (function () {
    eq('loose 127.1', t.parseLooseV4('127.1'), 2130706433);
    eq('loose 0x7f000001', t.parseLooseV4('0x7f000001'), 2130706433);
    eq('loose octal', t.parseLooseV4('0177.0.0.1'), 2130706433);
    eq('loose octal mixed', t.parseLooseV4('0177.0.0.1'), t.parseLooseV4('127.0.0.1'));
    eq('loose decimal', t.parseLooseV4('2130706433'), 2130706433);
    eq('loose with port', t.parseLooseV4('http://127.0.0.1:8080/x'), 2130706433);
    ok('loose rejects big octet', (function () {
      try { t.parseLooseV4('10.0.0.999'); return false; } catch (e) { return true; }
    })());

    var r = run('ssrf', 'gen', { host: '127.0.0.1', port: '80', scheme: 'http' }).out.result;
    has('ssrf dotted', r, '127.0.0.1');
    has('ssrf decimal', r, '2130706433');
    has('ssrf hex', r, '0x7f000001');
    has('ssrf octal', r, '0177.00.00.01');
    has('ssrf short', r, '127.1');
    has('ssrf v4-mapped', r, '[::ffff:127.0.0.1]');
    has('ssrf url decimal', r, 'http://2130706433:80/');
    has('ssrf localtest', r, 'localtest.me');
    has('ssrf metadata', r, '169.254.169.254');
    has('ssrf note', run('ssrf', 'gen', { host: '127.0.0.1' }).note, '127.0.0.1');

    var g = run('ssrf', 'gen', { host: '10.0.0.1', port: '8080', scheme: 'gopher' }).out.result;
    has('ssrf gopher', g, 'gopher://10.0.0.1:8080/_GET');

    has('ssrf hostname survives', run('ssrf', 'gen', { host: 'internal.corp' }).out.result, 'internal.corp');
    has('ssrf empty', run('ssrf', 'gen', {}).note, 'ERR:');
  })();

  /* ---- 10. redirect ---- */
  (function () {
    var r = run('redirect', 'gen', { evil: 'evil.example' });
    eq('redirect rows', lines(r.out.result), 15);
    has('redirect protocol-rel', r.out.result, '//evil.example');
    has('redirect no-slash', r.out.result, 'https:evil.example');
    has('redirect backslash', r.out.result, '/\\evil.example');
    has('redirect at', r.out.result, 'https://target.example@evil.example');
    has('redirect double-encoded', r.out.result, '/%2f%2e');
    has('redirect note', r.note, 'evil.example');
    has('redirect empty', run('redirect', 'gen', {}).note, 'ERR:');
  })();

  /* ---- 11. traversal ---- */
  (function () {
    var r = run('traversal', 'gen', { path: '/etc/passwd', prefix: '?file=' });
    eq('traversal rows', lines(r.out.result), 17);
    has('traversal depth1', r.out.result, '?file=../etc/passwd');
    has('traversal depth10', r.out.result, '?file=' + new Array(11).join('../') + 'etc/passwd');
    has('traversal double enc', r.out.result, '..%252f');
    has('traversal overlong', r.out.result, '..%c0%af');
    has('traversal filter evade', r.out.result, '....//');
    has('traversal null', r.out.result, '%00.png');
    has('traversal abs', r.out.result, '?file=/etc/passwd');
    has('traversal empty', run('traversal', 'gen', {}).note, 'ERR:');
  })();

  /* ---- 12. quotes ---- */
  (function () {
    var r = run('quotes', 'gen', { str: "admin'--" }).out.result;
    has('quotes hex literal', r, '0x61646d696e272d2d');
    has('quotes CHAR', r, 'CHAR(97,100,109,105,110,39,45,45)');
    has('quotes url', r, 'admin%27--');
    has('quotes doubled', r, "admin''--");
    has('quotes backslash', r, "admin\\'--");
    has('quotes empty', run('quotes', 'gen', {}).note, 'ERR:');
  })();

  /* ---- 13. wordmix ---- */
  (function () {
    var r = run('wordmix', 'gen', { name: 'acme', year: '2026' });
    var o = r.out.result;
    has('wordmix base', o, 'acme');
    has('wordmix year', o, 'acme2026');
    has('wordmix cap', o, 'Acme');
    has('wordmix bang', o, 'acme!1');
    has('wordmix Cap!1', o, 'Acme!1');
    has('wordmix leet', o, '4cm3');
    eq('wordmix count matches', String(r.out.count), String(lines(o)));
    ok('wordmix count is a number', /^\d+$/.test(r.out.count), r.out.count);

    var s = run('wordmix', 'gen', { name: 'acme', year: '2026', extras: 'summer,winter' });
    has('wordmix season+name', s.out.result, 'SummerAcme');
    has('wordmix name+season', s.out.result, 'AcmeSummer');
    ok('wordmix extras grow', Number(s.out.count) > Number(r.out.count), s.out.count);
    has('wordmix empty', run('wordmix', 'gen', {}).note, 'ERR:');
  })();

  /* ---- 14. cheat ---- */
  (function () {
    var all = run('cheat', 'look', {});
    eq('cheat total', lines(all.out.result), t.CHEATS.length);
    eq('cheat total is 62', t.CHEATS.length, 62);
    has('cheat note', all.note, t.CHEATS.length + ' of ' + t.CHEATS.length);
    has('cheat redis', run('cheat', 'look', { q: 'redis' }).out.result, 'redis-cli');
    has('cheat hat filter', run('cheat', 'look', { q: 'black' }).out.result, 'kerberoast');
    nohas('cheat hat filter excludes white', run('cheat', 'look', { q: 'black' }).out.result, 'whois');
    has('cheat none', run('cheat', 'look', { q: 'zzzz' }).out.result, '(nothing matched)');
    var hats = { white: 0, grey: 0, black: 0, common: 0 };
    t.CHEATS.forEach(function (c) { hats[{ w: 'white', g: 'grey', b: 'black', c: 'common' }[c[0]]]++; });
    ok('cheat hat split', hats.white === 14 && hats.grey === 9 && hats.black === 21 && hats.common === 18,
      JSON.stringify(hats));
  })();

  /* ---- 15. dorks ---- */
  (function () {
    ok('dork total is 47', t.DORKS.length === 47, t.DORKS.length);
    eq('dorks all rows', lines(run('dorks', 'look', {}).out.result), 47);
    eq('dorks cloud rows', lines(run('dorks', 'look', { cat: 'cloud' }).out.result), 4);
    has('dorks cloud aws', run('dorks', 'look', { cat: 'cloud' }).out.result, 'site:amazonaws.com "index of"');
    has('dorks cloud azure', run('dorks', 'look', { cat: 'cloud' }).out.result, 'blob.core.windows.net');
    has('dorks cloud gcs', run('dorks', 'look', { cat: 'cloud' }).out.result, 'storage.googleapis.com');
    has('dorks cloud do', run('dorks', 'look', { cat: 'cloud' }).out.result, 'digitaloceanspaces.com');
    eq('dorks filter aws', lines(run('dorks', 'look', { q: 'aws' }).out.result), 1);
    var none = run('dorks', 'look', { q: 'zzzzz' });
    has('dorks none text', none.out.result, '(nothing matched)');
    eq('dorks none note', none.note, '0 of 47 - recon reference, obey your scope');
    var cats = {};
    t.DORKS.forEach(function (d) { cats[d[0]] = (cats[d[0]] || 0) + 1; });
    ok('dorks 7 categories', Object.keys(cats).length === 7, JSON.stringify(cats));
    eq('dorks creds+files+dirs+cams+errors+info', cats.creds + cats.files + cats.dirs + cats.cams +
       cats.errors + cats.info, 43);
  })();

  /* ---- 16. dispatcher edge ---- */
  (function () {
    has('unknown tool', run('nope', 'x', {}).note, 'ERR: unknown tool');
    has('unknown action codec', run('codec', 'nope', { input: 'a' }).note, 'ERR:');
  })();

  var pass = R.filter(function (l) { return l.indexOf('PASS ') === 0; }).length;
  var fail = R.filter(function (l) { return l.indexOf('FAIL ') === 0; }).length;
  var head = 'TESTS ' + (pass + fail) + ' | PASS ' + pass + ' | FAIL ' + fail;
  window.__RESULTS = head + '\n' + R.join('\n');

  var el = document.getElementById('results');
  if (el) el.textContent = window.__RESULTS;
  else {
    var p = document.createElement('pre');
    p.id = 'results';
    p.textContent = window.__RESULTS;
    document.body.appendChild(p);
  }
})();
