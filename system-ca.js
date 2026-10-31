'use strict';

/**
 * system-ca.js — make BrowseFrame (Electron/Chromium) verify TLS against the
 * Debian system trust store (`ca-certificates`) instead of the CA snapshot that
 * is compiled into the Chromium/Node binaries shipped inside the AppImage/deb.
 *
 * The store is the pair of files the `ca-certificates` package maintains:
 *
 *      /etc/ssl/certs/ca-certificates.crt   bundle, rebuilt by update-ca-certificates
 *      /etc/ssl/certs/<hash>.0              per-CA links, same trigger
 *
 * Excluded roots (Debian's `!` entries in /etc/ca-certificates.conf, e.g. the
 * emSign ECC Root CA - G3 removal in DSA-6572-1) are absent from both files, so
 * a chain that depends on them fails to build and is rejected — see README.
 *
 * The store is re-stat'ed on every verification and its size+mtime is part of
 * the cache key, so an `apt upgrade ca-certificates` takes effect on the next
 * connection, without restarting BrowseFrame.
 *
 * Policy (the system store is authoritative):
 *
 *   chain contains a cert from the local blocklist -> REJECT (hard)
 *   system store says "revoked" (CRL hit)          -> REJECT (hard)
 *   system store verifies the chain               -> accept (Chromium's verdict
 *                                                    kept if it agreed, so CT
 *                                                    and pinning still apply)
 *   system store rejects the chain                -> REJECT (this is what makes
 *                                                    a distrusted root stop being
 *                                                    trusted)
 *   store unavailable / openssl missing / timeout  -> defer to Chromium
 *   chain not supplied by Chromium (leaf only)     -> defer to Chromium
 *
 * Environment knobs:
 *   BROWSEFRAME_CA_DIR          CA directory   (default: /etc/ssl/certs)
 *   BROWSEFRAME_CA_BUNDLE       CA bundle      (default: <CA_DIR>/ca-certificates.crt,
 *                                               then /etc/pki/tls/certs/ca-bundle.crt,
 *                                               /etc/ssl/cert.pem)
 *   BROWSEFRAME_BLOCKLIST       denylist file   (default: /etc/browseframe/blocked-certs.txt
 *                                                if it exists — see README; covers the
 *                                                window before apt ships the fix)
 *   BROWSEFRAME_UNTRUSTED_FALLBACK=1
 *                               fail open: if the store rejects a chain that Chromium
 *                               accepts, let Chromium win again (pre-patch behaviour;
 *                               do not use if you want distrust to propagate)
 *   BROWSEFRAME_STRICT_SYSTEM_CA=1
 *                               fail closed even when the store/openssl is unusable
 *   BROWSEFRAME_CA_DEBUG=1      log trust store + every verdict to stderr
 *   BROWSEFRAME_OPENSSL         openssl binary  (default: openssl)
 */

const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CA_DIR = process.env.BROWSEFRAME_CA_DIR || '/etc/ssl/certs';
const OPENSSL = process.env.BROWSEFRAME_OPENSSL || 'openssl';
const STRICT = process.env.BROWSEFRAME_STRICT_SYSTEM_CA === '1';
const FALLBACK = process.env.BROWSEFRAME_UNTRUSTED_FALLBACK === '1';
const DEBUG = process.env.BROWSEFRAME_CA_DEBUG === '1';
const BLOCKLIST_PATH =
  process.env.BROWSEFRAME_BLOCKLIST || '/etc/browseframe/blocked-certs.txt';

const VERIFY_TIMEOUT_MS = 5000;
const CACHE_TTL_MS = 60 * 1000;

// openssl X509_V_ERR_CERT_REVOKED
const X509_V_ERR_CERT_REVOKED = 23;

const BUNDLE_CANDIDATES = [
  process.env.BROWSEFRAME_CA_BUNDLE,
  path.join(CA_DIR, 'ca-certificates.crt'), // Debian / Ubuntu
  '/etc/pki/tls/certs/ca-bundle.crt', // Fedora / RHEL
  '/etc/ssl/cert.pem', // Alpine / misc
].filter(Boolean);

function log(...args) {
  if (DEBUG) console.error('[system-ca]', ...args);
}

function findBundle() {
  for (const candidate of BUNDLE_CANDIDATES) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/** Identity of the trust store right now — diagnostics + cache key. */
function trustStoreVersion() {
  const bundle = findBundle();
  if (!bundle) return 'none';
  try {
    const st = fs.statSync(bundle);
    return `${bundle}:${st.size}:${Math.floor(st.mtimeMs)}`;
  } catch {
    return 'unreadable';
  }
}

const BUNDLE = findBundle();

/* ------------------------------------------------------------------ */
/* PEM helpers                                                         */
/* ------------------------------------------------------------------ */

function splitChain(certificate) {
  const chain = [];
  let node = certificate;
  const seen = new Set();

  while (node && node.data) {
    const fp = node.fingerprint || node.data;
    if (seen.has(fp)) break; // self-signed / loop
    seen.add(fp);
    chain.push(node.data);
    node = node.issuerCert; // may be undefined
  }

  return { leafPem: chain[0] || null, chainPem: chain.slice(1).join('\n'), all: chain };
}

function pemBlocks(bundle) {
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(bundle)) !== null) out.push(m[0]);
  return out;
}

function pemToDer(pem) {
  // works for CERTIFICATE, PUBLIC KEY, X509 CRL ... blocks alike
  const body = pem
    .split('\n')
    .filter(line => !line.startsWith('-----'))
    .join('')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/* ------------------------------------------------------------------ */
/* optional local blocklist                                            */
/* ------------------------------------------------------------------ */

let blocklistCache = { key: null, value: { cert: new Set(), spki: new Set() } };

/**
 * Denylist file format (one entry per line, `#` comments):
 *
 *   cert-sha256:<hex>   SHA-256 over the DER cert  (openssl x509 -fingerprint -sha256)
 *   spki-sha256:<hex>   SHA-256 over the DER SubjectPublicKeyInfo
 *   <hex>               shorthand for cert-sha256
 *
 * Useful for the window between a CA compromise and the distro shipping a
 * ca-certificates update, and for keys you distrust regardless of the store.
 */
function loadBlocklist() {
  let st;
  try {
    st = fs.statSync(BLOCKLIST_PATH);
  } catch {
    blocklistCache = { key: null, value: { cert: new Set(), spki: new Set() } };
    return blocklistCache.value;
  }

  const key = `${BLOCKLIST_PATH}:${st.size}:${Math.floor(st.mtimeMs)}`;
  if (blocklistCache.key === key) return blocklistCache.value;

  const value = { cert: new Set(), spki: new Set() };
  try {
    for (const rawLine of fs.readFileSync(BLOCKLIST_PATH, 'utf8').split('\n')) {
      const line = rawLine.replace(/#.*$/, '').trim().toLowerCase();
      if (!line) continue;
      const sep = line.indexOf(':');
      if (sep === -1) {
        value.cert.add(line.replace(/[^0-9a-f]/g, ''));
      } else {
        const kind = line.slice(0, sep).trim();
        const hex = line.slice(sep + 1).replace(/[^0-9a-f]/g, '');
        if (!hex) continue;
        if (kind === 'spki-sha256') value.spki.add(hex);
        else if (kind === 'cert-sha256') value.cert.add(hex);
      }
    }
  } catch (err) {
    log(`blocklist unreadable: ${err.message}`);
  }
  log(`blocklist: ${value.cert.size} cert, ${value.spki.size} spki entries from ${BLOCKLIST_PATH}`);
  blocklistCache = { key, value };
  return value;
}

const spkiHashCache = new Map();

function spkiSha256Hex(pem) {
  if (spkiHashCache.has(pem)) return Promise.resolve(spkiHashCache.get(pem));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'browseframe-spki-'));
  const file = path.join(dir, 'cert.pem');
  try {
    fs.writeFileSync(file, pem);
  } catch {
    fs.rm(dir, { recursive: true, force: true }, () => {});
    return Promise.resolve(null);
  }
  return new Promise(resolve => {
    execFile(
      OPENSSL,
      ['x509', '-in', file, '-noout', '-pubkey'],
      { timeout: VERIFY_TIMEOUT_MS, maxBuffer: 1024 * 1024 },
      (err, stdout) => {
        fs.rm(dir, { recursive: true, force: true }, () => {});
        if (err || !stdout) return resolve(null);
        const hex = sha256Hex(pemToDer(stdout));
        spkiHashCache.set(pem, hex);
        resolve(hex);
      }
    );
  });
}

/** @returns {Promise<string|null>} matching entry description, or null */
async function blocklistHit(certs) {
  const list = loadBlocklist();
  if (list.cert.size === 0 && list.spki.size === 0) return null;

  for (const pem of certs) {
    if (list.cert.size) {
      const fp = sha256Hex(pemToDer(pem));
      if (list.cert.has(fp)) return `cert-sha256:${fp}`;
    }
    if (list.spki.size) {
      const fp = await spkiSha256Hex(pem);
      if (fp && list.spki.has(fp)) return `spki-sha256:${fp}`;
    }
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* openssl                                                             */
/* ------------------------------------------------------------------ */

function runOpenSSL(args) {
  return new Promise(resolve => {
    execFile(
      OPENSSL,
      args,
      { timeout: VERIFY_TIMEOUT_MS, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        // Distinguish "openssl could not run / timed out" (we cannot judge)
        // from "openssl ran and the chain failed to verify" (it can judge).
        const couldNotRun = Boolean(
          err && (err.code === 'ENOENT' || err.killed || err.signal || typeof err.code !== 'number')
        );
        resolve({
          ran: !couldNotRun,
          exitCode: err && typeof err.code === 'number' ? err.code : 0,
          stdout: stdout || '',
          stderr: stderr || '',
        });
      }
    );
  });
}

/**
 * Verify a leaf against the distro store.
 *
 *   pass 1  chain validation + hostname
 *   pass 2  same with -crl_check_all, used only for *positive* proof of
 *           revocation; a missing CRL (openssl error 3) is not a failure.
 *
 * @returns {Promise<{judged: boolean, ok: boolean, revoked: boolean, detail: string}>}
 */
async function verifyWithSystemStore({ hostname, leafPem, chainPem }) {
  if (!leafPem) {
    return { judged: false, ok: false, revoked: false, detail: 'no leaf certificate' };
  }

  const bundle = findBundle();
  let hasCApath = false;
  try {
    hasCApath = fs.statSync(CA_DIR).isDirectory();
  } catch {
    /* not there */
  }
  if (!bundle && !hasCApath) {
    return { judged: false, ok: false, revoked: false, detail: `no trust store at ${CA_DIR}` };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'browseframe-ca-'));
  const leafFile = path.join(dir, 'leaf.pem');
  const chainFile = path.join(dir, 'chain.pem');

  try {
    fs.writeFileSync(leafFile, leafPem);
    const hasChain = Boolean(chainPem && chainPem.trim());
    if (hasChain) fs.writeFileSync(chainFile, chainPem);

    const base = ['verify', '-CAfile', bundle, '-CApath', CA_DIR];
    if (hostname) base.push('-verify_hostname', hostname);
    if (hasChain) base.push('-untrusted', chainFile);

    const plain = await runOpenSSL([...base, leafFile]);
    const plainOut = plain.stdout + plain.stderr;
    const ok = plain.exitCode === 0 && /:\s*OK\b/.test(plain.stdout);
    log('pass1', hostname, ok ? 'OK' : 'FAIL', plainOut.trim().replace(/\s+/g, ' '));

    let revoked = false;
    if (ok) {
      const crl = await runOpenSSL([...base, '-crl_check_all', leafFile]);
      const crlOut = crl.stdout + crl.stderr;
      if (
        new RegExp(`error\\s+${X509_V_ERR_CERT_REVOKED}\\b`).test(crlOut) ||
        /certificate revoked/i.test(crlOut)
      ) {
        revoked = true;
      }
      log('pass2', hostname, revoked ? 'REVOKED' : 'not-revoked',
        crlOut.trim().replace(/\s+/g, ' '));
    }

    // Only a chain we were actually given can be judged: with a leaf-only
    // request we cannot tell "root distrusted" from "intermediate missing",
    // so a failure there defers to Chromium instead of rejecting.
    const judged = ok ? true : plain.ran && hasChain;
    if (plain.ran && !ok && !hasChain) {
      log('leaf-only request, cannot build a chain:', plainOut.trim().replace(/\s+/g, ' '));
    }

    return {
      judged,
      ok,
      revoked,
      detail: plainOut.trim().replace(/\s+/g, ' '),
    };
  } finally {
    fs.rm(dir, { recursive: true, force: true }, () => {});
  }
}

/* ------------------------------------------------------------------ */
/* Electron glue                                                       */
/* ------------------------------------------------------------------ */

/**
 * Install the verify proc on a Session. Call before the first loadURL().
 *
 * @param {Electron.Session} session
 */
function installSystemCA(session) {
  if (DEBUG) {
    let summary = 'no bundle found';
    if (BUNDLE) {
      try {
        const st = fs.statSync(BUNDLE);
        const count = (fs.readFileSync(BUNDLE, 'utf8').match(/BEGIN CERTIFICATE/g) || []).length;
        summary = `${BUNDLE} (${count} CAs, updated ${new Date(st.mtimeMs).toISOString()})`;
      } catch (err) {
        summary = `${BUNDLE} (unreadable: ${err.message})`;
      }
    }
    const bl = loadBlocklist();
    console.error(
      `[system-ca] trust store: ${summary}; CA dir: ${CA_DIR}; ` +
        `blocklist: ${bl.cert.size + bl.spki.size} entries; ` +
        `untrusted-fallback: ${FALLBACK}; strict: ${STRICT}`
    );
  }

  const cache = new Map(); // key -> { value, ts }

  session.setCertificateVerifyProc((request, callback) => {
    const { hostname, certificate, verificationResult } = request;
    const chromiumOk = verificationResult === 'OK';

    // Trust store identity is part of the key, so an apt upgrade of
    // ca-certificates invalidates cached verdicts immediately.
    const cacheKey = [
      hostname,
      certificate && certificate.serialNumber,
      certificate && certificate.validExpiry,
      trustStoreVersion(),
    ].join('|');

    const cached = cache.get(cacheKey);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
      callback(cached.value);
      return;
    }

    const decide = value => {
      cache.set(cacheKey, { value, ts: Date.now() });
      callback(value);
    };

    const { leafPem, chainPem, all } = splitChain(certificate);

    (async () => {
      const blocked = await blocklistHit(all);
      if (blocked) {
        log(`REJECT ${hostname}: blocklisted (${blocked})`);
        return -2;
      }

      const { judged, ok, revoked, detail } = await verifyWithSystemStore({
        hostname,
        leafPem,
        chainPem,
      });

      if (revoked) {
        log(`REJECT ${hostname}: certificate revoked (${detail})`);
        return -2;
      }
      if (ok) {
        // Store trusts it and the hostname matches. If Chromium agreed, keep
        // its verdict so Certificate Transparency / pinning still apply.
        return chromiumOk ? -3 : 0;
      }
      if (judged) {
        // The store evaluated this chain and refused it. This is the case that
        // makes a distrusted root (emSign ECC Root CA - G3, DSA-6572-1) stop
        // being trusted here, even though Chromium's baked root store still
        // carries it.
        if (FALLBACK && chromiumOk) {
          log(`ACCEPT ${hostname} via fallback: store refused (${detail})`);
          return -3;
        }
        log(`REJECT ${hostname}: not trusted by system store (${detail})`);
        return -2;
      }
      // Could not judge (no store, no openssl, timeout): defer to Chromium
      // unless strict mode forces a rejection.
      log(`DEFER ${hostname}: system store unusable (${detail})`);
      return chromiumOk && !STRICT ? -3 : -2;
    })()
      .then(decide)
      .catch(err => {
        log(`error for ${hostname}: ${err && err.message}`);
        decide(chromiumOk && !STRICT ? -3 : -2);
      });
  });
}

module.exports = {
  installSystemCA,
  verifyWithSystemStore,
  splitChain,
  trustStoreVersion,
  findBundle,
  pemBlocks,
  loadBlocklist,
  blocklistHit,
  CA_DIR,
  BUNDLE,
};
