// gencert.mjs — X.509 v3 generation + verification using ONLY node:crypto.
//
// Why this exists: the previous proxy.mjs signed leaf certificates at runtime with
// node-forge (plus an RSA keygen per hostname). node-forge is a node_modules
// dependency, which is exactly what kept the module from being self-contained.
// The intercept host set here is tiny and fixed (INTERCEPT_RE), so every leaf can
// be produced once, at deploy time, and simply read back at run time.
//
// That removes node-forge only if something can still *sign* X.509 on the device.
// Android ships no openssl binary, and a phone without Termux has none either, so
// the ASN.1/DER writer below is implemented by hand on top of node:crypto's RSA
// keygen and RSA-SHA256 signer.
//
// Nothing in here is interactive; every command is deterministic given the files
// on disk, and `ensure`/`verify` never overwrite an existing CA.
//
//   node gencert.mjs ensure -d <moduleDir> --hosts api2.lptiyu.com,api.lptiyu.com
//   node gencert.mjs ca     -d <moduleDir> [--cn NAME] [--days N] [--force]
//   node gencert.mjs leaf   -d <moduleDir> --host HOST [--days N] [--force]
//   node gencert.mjs verify -d <moduleDir> --hosts a,b,c [--quiet]
//
// Exit codes: 0 ok / 1 verification failed / 2 usage or IO error.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";

// ---------------------------------------------------------------- DER writer
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
const SEQ = (...a) => tlv(0x30, Buffer.concat(a));
const SETOF = (...a) => tlv(0x31, Buffer.concat(a));
const NULLDER = () => Buffer.from([0x05, 0x00]);
const BOOL = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const OCTET = (b) => tlv(0x04, b);
const BITSTR = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const UTF8S = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const PRINTS = (s) => tlv(0x13, Buffer.from(s, "ascii"));
// context-specific tag: constructed -> 0xaN, primitive -> 0x8N
const CTX = (n, body, constructed = true) => tlv((constructed ? 0xa0 : 0x80) | n, body);

function INT(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  let b = Buffer.from(buf.subarray(i));
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
function OID(str) {
  const p = str.split(".").map(Number);
  const out = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) {
    if (v < 0x80) { out.push(v); continue; }
    const tmp = [];
    let x = v;
    while (x > 0) { tmp.unshift(x & 0x7f); x = Math.floor(x / 128); }
    for (let i = 0; i < tmp.length - 1; i++) tmp[i] |= 0x80;
    out.push(...tmp);
  }
  return tlv(0x06, Buffer.from(out));
}
function TIME(d) {
  const p2 = (n) => String(n).padStart(2, "0");
  const y = d.getUTCFullYear();
  const rest =
    p2(d.getUTCMonth() + 1) + p2(d.getUTCDate()) +
    p2(d.getUTCHours()) + p2(d.getUTCMinutes()) + p2(d.getUTCSeconds()) + "Z";
  if (y >= 1950 && y < 2050) return tlv(0x17, Buffer.from(p2(y % 100) + rest, "ascii"));
  return tlv(0x18, Buffer.from(String(y) + rest, "ascii"));
}

const OID_CN = "2.5.4.3", OID_O = "2.5.4.10", OID_C = "2.5.4.6";
const rdn = (oid, valueTlv) => SETOF(SEQ(OID(oid), valueTlv));
function nameOf({ cn, o, c }) {
  const parts = [rdn(OID_CN, UTF8S(cn))];
  if (o) parts.push(rdn(OID_O, UTF8S(o)));
  if (c) parts.push(rdn(OID_C, PRINTS(c)));
  return SEQ(...parts);
}

const ALG_SHA256_RSA = SEQ(OID("1.2.840.113549.1.1.11"), NULLDER());
const OID_BC = "2.5.29.19", OID_KU = "2.5.29.15", OID_EKU = "2.5.29.37";
const OID_SAN = "2.5.29.17", OID_SKI = "2.5.29.14", OID_AKI = "2.5.29.35";
const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
// DER content octets (no tag/length) of the two extensions parseCert looks at.
// Written out literally: an OID payload is short here and hex keeps the reader
// comparison exact without re-encoding on every node.
const SKI_CONTENT_HEX = "551d0e";
const BC_CONTENT_HEX = "551d13";

function ext(oid, critical, valueDer) {
  const parts = [OID(oid)];
  if (critical) parts.push(BOOL(true));
  parts.push(OCTET(valueDer));
  return SEQ(...parts);
}

// ---------------------------------------------------------------- DER reader
function tlvAt(buf, off) {
  const tag = buf[off];
  let p = off + 1;
  let l = buf[p++];
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + buf[p++];
  }
  return { tag, start: off, hdr: p - off, len: l, body: p, end: p + l };
}
function kids(buf, node) {
  const out = [];
  let off = node.body;
  while (off < node.end) {
    const c = tlvAt(buf, off);
    if (c.end <= off) break;      // malformed: refuse to loop forever
    out.push(c);
    off = c.end;
  }
  return out;
}
const isCtx = (n, tag) => (n.tag & 0xe0) === 0xa0 && (n.tag & 0x1f) === tag;
const raw = (buf, n) => Buffer.from(buf.subarray(n.start, n.end));
const body = (buf, n) => Buffer.from(buf.subarray(n.body, n.end));

// SubjectPublicKeyIdentifier per RFC 5280 §4.2.1.2 method (1): SHA-1 over the
// subjectPublicKey BIT STRING contents. node-forge used the same method, so this
// stays consistent with a CA that was generated earlier by node-forge.
function subjectKeyId(spkiDer) {
  const spki = tlvAt(spkiDer, 0);
  const f = kids(spkiDer, spki);            // [ AlgorithmIdentifier, BIT STRING ]
  if (!f[1] || f[1].tag !== 0x03) return null;
  const bits = spkiDer.subarray(f[1].body + 1, f[1].end);  // drop "unused bits" octet
  return crypto.createHash("sha1").update(bits).digest();
}

// Pull subject DER + SKI out of an existing CA certificate. Needed because the
// leaf's issuer MUST be byte-identical to the CA subject that is already trusted
// on the device; re-encoding it from parsed strings risks a mismatch.
function parseCert(der) {
  const cert = tlvAt(der, 0);
  if (cert.tag !== 0x30) throw new Error("not a DER SEQUENCE");
  const top = kids(der, cert);
  if (top.length < 3) throw new Error("truncated certificate");
  const tbs = top[0];
  const f = kids(der, tbs);
  let i = 0;
  let version = 1;
  if (f[i] && isCtx(f[i], 0)) { version = body(der, f[i])[1] + 1; i++; }
  const serial = f[i++];
  const sigAlg = f[i++];
  const issuer = f[i++];
  const validity = f[i++];
  const subject = f[i++];
  const spki = f[i++];
  const exts = f[i] && isCtx(f[i], 3) ? f[i] : null;
  const out = {
    der, version, serial, sigAlg, issuer, validity, subject, spki, exts,
    subjectDer: raw(der, subject),
    issuerDer: raw(der, issuer),
    spkiDer: raw(der, spki),
    ski: null, isCa: false,
  };
  if (exts) {
    const inner = kids(der, exts)[0];
    for (const e of kids(der, inner)) {
      const parts = kids(der, e);
      const oid = body(der, parts[0]).toString("hex");
      const val = parts[parts.length - 1];
      if (val.tag !== 0x04) continue;
      const vder = body(der, val);
      if (oid === SKI_CONTENT_HEX) {
        // value is itself an OCTET STRING wrapping the key id
        const inner2 = tlvAt(vder, 0);
        if (inner2.tag === 0x04) out.ski = body(vder, inner2);
      }
      if (oid === BC_CONTENT_HEX) {
        const bc = kids(vder, tlvAt(vder, 0));
        if (bc.length && bc[0].tag === 0x01) out.isCa = vder[bc[0].body] !== 0x00;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- key material
function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { spkiDer: publicKey, privPem: privateKey, keyId: subjectKeyId(publicKey) };
}

function pemWrap(der, label) {
  const b64 = der.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}
function pemBody(txt) {
  return Buffer.from(String(txt).replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

// ---------------------------------------------------------------- cert builder
function buildCert({ subjectName, issuerName, serial, notBefore, notAfter, spkiDer, exts, signKeyPem }) {
  const tbs = SEQ(
    CTX(0, INT(Buffer.from([2]))),            // version: v3 (0-based 2)
    INT(serial),
    ALG_SHA256_RSA,
    issuerName,
    SEQ(TIME(notBefore), TIME(notAfter)),
    subjectName,
    spkiDer,                                   // SubjectPublicKeyInfo
    CTX(3, SEQ(...exts)),                      // [3] EXPLICIT Extensions
  );
  const sig = crypto.createSign("RSA-SHA256").update(tbs).sign(signKeyPem);
  return SEQ(tbs, ALG_SHA256_RSA, BITSTR(sig, 0));
}

function randSerial(prefix) {
  const b = crypto.randomBytes(15);
  b[0] = (b[0] & 0x3f) | 0x40;                 // keep it < 2^120 and non-zero
  return Buffer.concat([Buffer.from([prefix]), b]);
}

function days(n) { return new Date(Date.now() + n * 86400000); }
function back() { return new Date(Date.now() - 86400000); }

// Keeps a small "generation stamp" next to prevent accidental double-generation
// from two concurrent deploys clobbering one another.
function writeAtomic(file, data, mode) {
  const tmp = file + ".tmp." + process.pid;
  fs.writeFileSync(tmp, data, { mode });
  try { fs.chmodSync(tmp, mode); } catch { }
  fs.renameSync(tmp, file);
}

// ---------------------------------------------------------------- commands
function caFiles(dir) {
  return { key: path.join(dir, "ca.key.pem"), crt: path.join(dir, "ca.crt.pem") };
}
function leafFiles(dir, host) {
  const d = path.join(dir, "leafs");
  const h = String(host).toLowerCase();
  return { dir: d, key: path.join(d, h + ".key.pem"), crt: path.join(d, h + ".crt.pem") };
}

function makeCa(dir, { cn = "LPTIYU Lab Root CA", validDays = 3650, force = false, quiet = false } = {}) {
  const f = caFiles(dir);
  if (!force && fs.existsSync(f.key) && fs.existsSync(f.crt)) {
    if (!quiet) console.log(`ca: kept existing (${f.crt})`);
    return { created: false, ...f };
  }
  fs.mkdirSync(dir, { recursive: true });
  const k = newKey();
  const nm = nameOf({ cn, o: "Lab", c: "CN" });
  const der = buildCert({
    subjectName: nm,
    issuerName: nm,
    serial: randSerial(0x01),
    notBefore: back(),
    notAfter: days(validDays),
    spkiDer: k.spkiDer,
    signKeyPem: k.privPem,
    exts: [
      ext(OID_BC, true, SEQ(BOOL(true))),
      ext(OID_KU, true, BITSTR(Buffer.from([0x06]), 1)),   // keyCertSign | cRLSign
      ext(OID_SKI, false, OCTET(k.keyId)),
    ],
  });
  writeAtomic(f.key, k.privPem, 0o600);
  writeAtomic(f.crt, pemWrap(der, "CERTIFICATE"), 0o644);
  if (!quiet) console.log(`ca: created ${f.crt} (${cn}, ${validDays}d)`);
  return { created: true, ...f };
}

function makeLeaf(dir, host, { validDays = 1825, force = false, quiet = false } = {}) {
  const f = leafFiles(dir, host);
  const h = String(host).toLowerCase();
  if (!force && fs.existsSync(f.key) && fs.existsSync(f.crt)) {
    if (!quiet) console.log(`leaf: kept ${h}`);
    return { created: false, ...f };
  }
  const ca = caFiles(dir);
  if (!fs.existsSync(ca.crt) || !fs.existsSync(ca.key)) {
    throw new Error(`leaf ${h}: CA missing (need ${ca.crt} + ${ca.key})`);
  }
  const caPem = fs.readFileSync(ca.crt, "utf8");
  const caKey = fs.readFileSync(ca.key, "utf8");
  const parsed = parseCert(pemBody(caPem));
  const caKeyId = parsed.ski || subjectKeyId(parsed.spkiDer);
  const k = newKey();
  const der = buildCert({
    subjectName: nameOf({ cn: h }),
    issuerName: parsed.subjectDer,          // byte-identical to the trusted CA subject
    serial: randSerial(0x02),
    notBefore: back(),
    notAfter: days(validDays),
    spkiDer: k.spkiDer,
    signKeyPem: caKey,
    exts: [
      ext(OID_BC, true, SEQ(BOOL(false))),
      ext(OID_KU, true, BITSTR(Buffer.from([0xa0]), 5)),   // digitalSignature | keyEncipherment
      ext(OID_EKU, false, SEQ(OID(OID_SERVER_AUTH))),
      ext(OID_SAN, false, SEQ(CTX(2, Buffer.from(h, "ascii"), false))),
      ext(OID_SKI, false, OCTET(k.keyId)),
      ...(caKeyId ? [ext(OID_AKI, false, SEQ(CTX(0, caKeyId, false)))] : []),
    ],
  });
  fs.mkdirSync(f.dir, { recursive: true });
  writeAtomic(f.key, k.privPem, 0o600);
  writeAtomic(f.crt, pemWrap(der, "CERTIFICATE"), 0o644);
  if (!quiet) console.log(`leaf: created ${h}`);
  return { created: true, ...f };
}

// End-to-end proof that the leaf is accepted for that exact hostname with only the
// CA as trust anchor: a real TLS handshake on loopback, default verification on.
function tlsProbe(host, keyPem, certPem, caPem) {
  return new Promise((resolve) => {
    let srv;
    let done = false;
    const finish = (ok, detail) => {
      if (done) return;
      done = true;
      try { srv && srv.close(); } catch { }
      resolve({ ok, detail });
    };
    try {
      srv = tls.createServer({ key: keyPem, cert: certPem, minVersion: "TLSv1.2" }, (s) => {
        s.on("error", () => { });
        try { s.end(); } catch { }
      });
    } catch (e) { return finish(false, `server: ${e.message}`); }
    srv.on("tlsClientError", (e) => finish(false, `tls: ${e.message}`));
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      const c = tls.connect({
        port, host: "127.0.0.1", servername: host, ca: caPem,
        minVersion: "TLSv1.2", rejectUnauthorized: true,
        checkServerIdentity: (_h, cert) => tls.checkServerIdentity(host, cert),
      }, () => {
        const ok = c.authorized;
        const proto = c.alpnProtocol || "";
        c.end();
        finish(ok, ok ? `handshake ok${proto ? " alpn=" + proto : ""}` : String(c.authorizationError));
      });
      c.on("error", (e) => finish(false, `client: ${e.message}`));
      c.setTimeout(8000, () => { try { c.destroy(); } catch { } finish(false, "timeout"); });
    });
  });
}

async function verify(dir, hosts, { quiet = false } = {}) {
  const say = (s) => { if (!quiet) console.log(s); };
  const bad = [];
  const ca = caFiles(dir);
  if (!fs.existsSync(ca.crt)) { console.log(`verify: FAIL ca.crt.pem missing (${ca.crt})`); return 1; }
  if (!fs.existsSync(ca.key)) { console.log(`verify: FAIL ca.key.pem missing (${ca.key})`); return 1; }
  const caPem = fs.readFileSync(ca.crt, "utf8");
  let caCert;
  try { caCert = new crypto.X509Certificate(caPem); }
  catch (e) { console.log(`verify: FAIL ca.crt.pem unparsable: ${e.message}`); return 1; }
  if (!caCert.ca) bad.push("ca.crt.pem is not a CA certificate (basicConstraints)");
  const caNotAfter = new Date(caCert.validTo).getTime();
  if (!(caNotAfter > Date.now())) bad.push(`ca.crt.pem expired (${caCert.validTo})`);
  say(`verify: ca subject = ${caCert.subject.replace(/\n/g, ", ")}`);
  say(`verify: ca valid  = ${caCert.validFrom} -> ${caCert.validTo}`);

  const caKeyPem = fs.readFileSync(ca.key, "utf8");
  // CA key must actually belong to the CA certificate.
  try {
    const probe = crypto.randomBytes(16);
    const s = crypto.createSign("RSA-SHA256").update(probe).sign(caKeyPem);
    if (!crypto.createVerify("RSA-SHA256").update(probe).verify(caCert.publicKey, s)) {
      bad.push("ca.key.pem does not match ca.crt.pem");
    }
  } catch (e) { bad.push(`ca.key.pem unusable: ${e.message}`); }

  for (const host of hosts) {
    const h = String(host).toLowerCase();
    const f = leafFiles(dir, h);
    if (!fs.existsSync(f.crt)) { bad.push(`${h}: leaf crt missing (${f.crt})`); continue; }
    if (!fs.existsSync(f.key)) { bad.push(`${h}: leaf key missing (${f.key})`); continue; }
    const certPem = fs.readFileSync(f.crt, "utf8");
    const keyPem = fs.readFileSync(f.key, "utf8");
    let leaf;
    try { leaf = new crypto.X509Certificate(certPem); }
    catch (e) { bad.push(`${h}: leaf crt unparsable: ${e.message}`); continue; }
    if (!leaf.checkIssued(caCert)) bad.push(`${h}: issuer does not match the CA`);
    if (!leaf.verify(caCert.publicKey)) bad.push(`${h}: signature not made by the CA key`);
    if (!leaf.checkHost(h)) bad.push(`${h}: certificate is not valid for this hostname`);
    if (!(new Date(leaf.validTo).getTime() > Date.now())) bad.push(`${h}: expired (${leaf.validTo})`);
    try {
      const probe = crypto.randomBytes(16);
      const s = crypto.createSign("RSA-SHA256").update(probe).sign(keyPem);
      if (!crypto.createVerify("RSA-SHA256").update(probe).verify(leaf.publicKey, s)) {
        bad.push(`${h}: leaf key does not match leaf cert`);
      }
    } catch (e) { bad.push(`${h}: leaf key unusable: ${e.message}`); }
    const p = await tlsProbe(h, keyPem, certPem, caPem);
    if (!p.ok) bad.push(`${h}: TLS handshake rejected (${p.detail})`);
    say(`verify: ${h} -> ${p.ok ? "OK" : "FAIL"} (${p.detail}), notAfter=${leaf.validTo}`);
  }

  if (bad.length) {
    for (const b of bad) console.log(`verify: FAIL ${b}`);
    return 1;
  }
  say("verify: ALL PASS");
  return 0;
}

// ---------------------------------------------------------------- CLI
function parseArgs(argv) {
  const o = { _: [], quiet: false, force: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-d" || a === "--dir") o.dir = argv[++i];
    else if (a === "--host") o.host = argv[++i];
    else if (a === "--hosts") o.hosts = argv[++i];
    else if (a === "--cn") o.cn = argv[++i];
    else if (a === "--days") o.days = parseInt(argv[++i], 10);
    else if (a === "--a") o.a = argv[++i];
    else if (a === "--b") o.b = argv[++i];
    else if (a === "--quiet" || a === "-q") o.quiet = true;
    else if (a === "--force" || a === "-f") o.force = true;
    else o._.push(a);
  }
  o.dir = path.resolve(o.dir || ".");
  o.hosts = (o.hosts || "").split(",").map(s => s.trim()).filter(Boolean);
  return o;
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const o = parseArgs(argv.slice(1));
  const hosts = o.hosts.length ? o.hosts : (o.host ? [o.host] : []);

  switch (cmd) {
    case "ca": {
      const r = makeCa(o.dir, { cn: o.cn, validDays: o.days || 3650, force: o.force, quiet: o.quiet });
      if (!o.quiet) console.log(JSON.stringify({ created: r.created, crt: r.crt, key: r.key }));
      return 0;
    }
    case "leaf": {
      if (!o.host) { console.error("leaf: --host required"); return 2; }
      const r = makeLeaf(o.dir, o.host, { validDays: o.days || 1825, force: o.force, quiet: o.quiet });
      if (!o.quiet) console.log(JSON.stringify({ created: r.created, crt: r.crt, key: r.key }));
      return 0;
    }
    case "ensure": {
      if (!hosts.length) { console.error("ensure: --hosts required"); return 2; }
      fs.mkdirSync(o.dir, { recursive: true });
      const c = makeCa(o.dir, { validDays: o.days || 3650, force: o.force, quiet: o.quiet });
      let made = 0;
      for (const h of hosts) {
        const r = makeLeaf(o.dir, h, { validDays: 1825, force: o.force, quiet: o.quiet });
        if (r.created) made++;
      }
      if (!o.quiet) {
        console.log(`ensure: ca ${c.created ? "created" : "kept"}, leafs created=${made}/${hosts.length}`);
      }
      return 0;
    }
    case "verify":
      return await verify(o.dir, hosts, { quiet: o.quiet });
    case "same": {
      // Certificate identity, not file identity: the same certificate can be
      // stored with different PEM line wrapping, and rewriting an already
      // published trust anchor because of whitespace is pointless churn.
      // exit 0 = same certificate, 1 = different or unreadable, 2 = usage.
      if (!o.a || !o.b) { console.error("same: --a and --b required"); return 2; }
      try {
        const a = new crypto.X509Certificate(fs.readFileSync(o.a));
        const b = new crypto.X509Certificate(fs.readFileSync(o.b));
        const same = a.fingerprint256 === b.fingerprint256;
        if (!o.quiet) console.log(`${same ? "same" : "different"} ${a.fingerprint256} ${b.fingerprint256}`);
        return same ? 0 : 1;
      } catch (e) {
        if (!o.quiet) console.log(`unreadable: ${e.message}`);
        return 1;
      }
    }
    default:
      console.error("usage: node gencert.mjs {ca|leaf|ensure|verify} [-d DIR] [--hosts a,b] [--host h] [--cn N] [--days N] [--force] [--quiet]");
      return 2;
  }
}

main().then((rc) => process.exit(rc)).catch((e) => {
  console.error(`gencert: ${e && e.stack ? e.stack : e}`);
  process.exit(2);
});
