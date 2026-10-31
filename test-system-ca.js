'use strict';

/**
 * Offline test for system-ca.js.
 *
 * Builds a throwaway 3-level PKI (root -> intermediate -> leaf), a store that
 * mimics /etc/ssl/certs (bundle + rehashed links + a CRL), and drives the real
 * installSystemCA() with fake Electron requests. Scenarios 8-10 replay the
 * eMudhra/emSign DSA-6572-1 shape: a root that upstream removes from the store.
 *
 *   node test-system-ca.js
 */

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'bfca-test-'));
const PKI = path.join(ROOT, 'pki');
const STORE = path.join(ROOT, 'etc-ssl-certs');
const INTCFG = path.join(PKI, 'int.cnf');

const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { stdio: 'pipe', ...opts });

function sh(cmd, args) {
  try {
    return run(cmd, args).toString();
  } catch (err) {
    return `${err.stdout || ''}${err.stderr || ''}`;
  }
}

/* ------------------------------------------------------------------ */
/* PKI                                                                 */
/* ------------------------------------------------------------------ */

fs.mkdirSync(path.join(PKI, 'intdb', 'newcerts'), { recursive: true });
fs.mkdirSync(STORE, { recursive: true });
fs.writeFileSync(path.join(PKI, 'intdb', 'index.txt'), '');
fs.writeFileSync(path.join(PKI, 'intdb', 'serial'), '1000\n');
fs.writeFileSync(path.join(PKI, 'intdb', 'crlnumber'), '1000\n');

const p = name => path.join(PKI, name);

sh('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', p('root.key'), '-out', p('root.pem'), '-days', '3650',
  '-subj', '/CN=Test Trusted Root CA']);

sh('openssl', ['req', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', p('int.key'), '-out', p('int.csr'), '-subj', '/CN=Test Intermediate CA']);
fs.writeFileSync(p('int.ext'),
  'basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\n');
sh('openssl', ['x509', '-req', '-in', p('int.csr'), '-CA', p('root.pem'),
  '-CAkey', p('root.key'), '-CAcreateserial', '-out', p('int.pem'), '-days', '3000',
  '-extfile', p('int.ext')]);

fs.writeFileSync(INTCFG, `
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ${path.join(PKI, 'intdb')}
database = $dir/index.txt
serial = $dir/serial
crlnumber = $dir/crlnumber
new_certs_dir = $dir/newcerts
certificate = ${p('int.pem')}
private_key = ${p('int.key')}
default_md = sha256
policy = pol
default_days = 825
default_crl_days = 30
[ pol ]
commonName = supplied
`);

function makeLeaf(name, cn) {
  sh('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', p(`${name}.key`),
    '-out', p(`${name}.csr`), '-subj', `/CN=${cn}`]);
  fs.writeFileSync(p(`${name}.ext`), [
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage = serverAuth',
    `subjectAltName = DNS:${cn}`,
    '',
  ].join('\n'));
  sh('openssl', ['ca', '-batch', '-config', INTCFG, '-in', p(`${name}.csr`),
    '-out', p(`${name}.pem`), '-extfile', p(`${name}.ext`)]);
  return fs.readFileSync(p(`${name}.pem`), 'utf8');
}

const goodLeaf = makeLeaf('good', 'intranet.internal');
const revokedLeaf = makeLeaf('revoked', 'revoked.internal');

// revoke + publish the intermediate's CRL
sh('openssl', ['ca', '-batch', '-config', INTCFG, '-revoke', p('revoked.pem')]);
sh('openssl', ['ca', '-batch', '-config', INTCFG, '-gencrl', '-out', p('int.crl')]);

// a self-signed leaf whose CA is not in the store at all
sh('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', p('orphan.key'), '-out', p('orphan.pem'), '-days', '365',
  '-subj', '/CN=orphan.internal', '-addext', 'subjectAltName=DNS:orphan.internal']);
const orphanLeaf = fs.readFileSync(p('orphan.pem'), 'utf8');

const rootPem = fs.readFileSync(p('root.pem'), 'utf8');
const intPem = fs.readFileSync(p('int.pem'), 'utf8');

/* ------------------------------------------------------------------ */
/* store                                                               */
/* ------------------------------------------------------------------ */

const BUNDLE = path.join(STORE, 'ca-certificates.crt');

function buildStore({ withRoot = true, withCrl = true } = {}) {
  for (const f of fs.readdirSync(STORE)) fs.rmSync(path.join(STORE, f), { force: true });
  fs.writeFileSync(BUNDLE, withRoot ? rootPem : '');
  fs.writeFileSync(path.join(STORE, 'root.pem'), withRoot ? rootPem : '# removed\n');
  if (withCrl) fs.copyFileSync(p('int.crl'), path.join(STORE, 'int.crl'));
  sh('openssl', ['rehash', STORE]);
  // rehash leaves dangling links for files that are not certificates; drop them
  for (const f of fs.readdirSync(STORE)) {
    if (!/^\w{8}\.[0-9r]+$/.test(f)) continue;
    try {
      const target = fs.realpathSync(path.join(STORE, f));
      const content = fs.readFileSync(target, 'utf8');
      if (!content.includes('BEGIN CERTIFICATE') && !content.includes('BEGIN X509 CRL')) {
        fs.rmSync(path.join(STORE, f), { force: true });
      }
    } catch {
      fs.rmSync(path.join(STORE, f), { force: true });
    }
  }
}

buildStore();

/* ------------------------------------------------------------------ */
/* harness                                                             */
/* ------------------------------------------------------------------ */

const ENV_KEYS = [
  'BROWSEFRAME_CA_DIR', 'BROWSEFRAME_CA_BUNDLE', 'BROWSEFRAME_BLOCKLIST',
  'BROWSEFRAME_OPENSSL', 'BROWSEFRAME_UNTRUSTED_FALLBACK',
  'BROWSEFRAME_STRICT_SYSTEM_CA', 'BROWSEFRAME_CA_DEBUG',
];

function load(vars) {
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, { BROWSEFRAME_CA_DIR: STORE }, vars);
  delete require.cache[require.resolve('./system-ca')];
  return require('./system-ca');
}

/** Build the fake Electron `request` for a leaf + served chain. */
function fakeRequest(leafPem, hostname, chromiumResult, chainPems = [intPem]) {
  let node;
  for (let i = chainPems.length - 1; i >= 0; i--) {
    node = { data: chainPems[i], fingerprint: crypto.createHash('sha256').update(chainPems[i]).digest('hex'), issuerCert: node };
  }
  const certificate = {
    data: leafPem,
    serialNumber: crypto.createHash('sha256').update(leafPem).digest('hex').slice(0, 16),
    validExpiry: Math.floor(Date.now() / 1000) + 3600,
    fingerprint: crypto.createHash('sha256').update(leafPem).digest('hex'),
    issuerCert: node,
  };
  return {
    hostname,
    certificate,
    validatedCertificate: certificate,
    isIssuedByKnownRoot: false,
    verificationResult: chromiumResult,
    errorCode: chromiumResult === 'OK' ? 0 : -202,
  };
}

function decide(mod, request) {
  let proc;
  mod.installSystemCA({ setCertificateVerifyProc: fn => { proc = fn; } });
  return new Promise(resolve => proc(request, resolve));
}

const results = [];
function check(name, got, want) {
  results.push({ name, ok: got === want, got, want });
}

/* ------------------------------------------------------------------ */
/* scenarios                                                           */
/* ------------------------------------------------------------------ */

(async () => {
  // ---- 1-7: baseline behaviour with a healthy store -------------------
  let mod = load({});

  check('private CA, Chromium error -> accept', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'CERT_AUTHORITY_INVALID')), 0);
  check('private CA, Chromium ok -> Chromium verdict kept', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -3);
  check('hostname mismatch -> reject', await decide(mod, fakeRequest(goodLeaf, 'evil.example', 'CERT_COMMON_NAME_INVALID')), -2);
  check('revoked leaf, Chromium ok -> reject (CRL)', await decide(mod, fakeRequest(revokedLeaf, 'revoked.internal', 'OK')), -2);
  check('revoked leaf, Chromium error -> reject', await decide(mod, fakeRequest(revokedLeaf, 'revoked.internal', 'CERT_REVOKED')), -2);
  check('self-signed leaf (no chain), Chromium ok -> defer', await decide(mod, fakeRequest(orphanLeaf, 'orphan.internal', 'OK', [])), -3);
  check('self-signed leaf (no chain), Chromium error -> reject', await decide(mod, fakeRequest(orphanLeaf, 'orphan.internal', 'CERT_AUTHORITY_INVALID', [])), -2);
  check('root also served in chain, anchor present -> accept', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK', [intPem, rootPem])), -3);

  // ---- 8-10: the eMudhra shape (root removed by the distro) ----------
  check('eMudhra sim step 1: root present -> accept', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -3);

  buildStore({ withRoot: false });          // ← what `apt upgrade ca-certificates` does
  mod = load({});                            // same code, new store on disk
  check('eMudhra sim step 2: root removed, Chromium still trusts it -> REJECT',
    await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -2);

  mod = load({ BROWSEFRAME_UNTRUSTED_FALLBACK: '1' });
  check('eMudhra sim step 2 with UNTRUSTED_FALLBACK=1 -> accept again',
    await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -3);

  // ---- 11-12: local blocklist, before apt ships anything -------------
  buildStore({ withRoot: true });            // unpatched device
  const certHash = crypto.createHash('sha256').update(
    Buffer.from(intPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, ''), 'base64')
  ).digest('hex');
  const spkiPem = sh('openssl', ['x509', '-in', p('int.pem'), '-noout', '-pubkey']);
  const spkiHash = crypto.createHash('sha256').update(
    Buffer.from(spkiPem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, ''), 'base64')
  ).digest('hex');

  const BL1 = path.join(ROOT, 'blocked-cert.txt');
  fs.writeFileSync(BL1, `# compromised intermediate\ncert-sha256:${certHash}\n`);
  mod = load({ BROWSEFRAME_BLOCKLIST: BL1 });
  check('blocklist cert-sha256 hit -> reject even though root is trusted',
    await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -2);

  const BL2 = path.join(ROOT, 'blocked-spki.txt');
  fs.writeFileSync(BL2, `spki-sha256:${spkiHash}\n`);
  mod = load({ BROWSEFRAME_BLOCKLIST: BL2 });
  check('blocklist spki-sha256 hit -> reject',
    await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -2);

  mod = load({ BROWSEFRAME_BLOCKLIST: path.join(ROOT, 'nonexistent.txt') });
  check('missing blocklist -> no effect', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -3);

  // ---- 13-15: degraded environments ----------------------------------
  mod = load({ BROWSEFRAME_OPENSSL: '/nonexistent/openssl' });
  check('openssl missing, Chromium ok -> defer to Chromium', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -3);

  mod = load({ BROWSEFRAME_OPENSSL: '/nonexistent/openssl', BROWSEFRAME_STRICT_SYSTEM_CA: '1' });
  check('openssl missing, strict -> reject', await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'OK')), -2);

  // bundle only, no rehashed links (pure ca-certificates.crt layout)
  const BUNDLE_ONLY = path.join(ROOT, 'bundle-only');
  fs.mkdirSync(BUNDLE_ONLY, { recursive: true });
  fs.writeFileSync(path.join(BUNDLE_ONLY, 'ca-certificates.crt'), rootPem);
  mod = load({ BROWSEFRAME_CA_DIR: BUNDLE_ONLY });
  check('bundle-only store -> private CA accepted',
    await decide(mod, fakeRequest(goodLeaf, 'intranet.internal', 'CERT_AUTHORITY_INVALID')), 0);

  // ---- report --------------------------------------------------------
  let failed = 0;
  for (const r of results) {
    if (!r.ok) failed++;
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}: got ${r.got}, want ${r.want}`);
  }
  console.log(`\nstore: ${STORE}`);
  console.log(failed === 0 ? 'ALL PASS' : `${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
