// tanke transparent MITM proxy (v2) — per-app, iptables REDIRECT based.
//
// Why v2: v1 relied on the system-wide `http_proxy` setting, which funnels EVERY
// app's HTTP(S) through this process. Any weakness here (= whole phone offline).
// v2 is never selected by the system proxy setting. Only traffic that iptables
// redirects (uid of com.lptiyu.tanke -> api2.lptiyu.com IPs, tcp/443) lands here.
// No CONNECT indirection => no header/ClientHello pipelining loss, no DNS
// dependency in the hot path (upstream IP is pinned, SNI carries the hostname).
//
// Modes auto-detected on the first bytes of a connection:
//   0x16 ...      -> transparent TLS (REDIRECT target): MITM only if SNI is an
//                    intercept host, otherwise byte-for-byte passthrough.
//   "CONNECT ..." -> legacy HTTP proxy mode (kept for debugging only).
//   anything else -> plain HTTP request.
//
// Version-gate bypass logic is unchanged from v1 (verified against real traffic):
//   request : version_name 4.2.0 -> 4.3.0, version 220 -> 233, sign recomputed
//   response: system/update rewritten to "already up to date"
import net from "node:net";
import tls from "node:tls";
import https from "node:https";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import dgram from "node:dgram";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

// ---- version-gate rewrite + resign (RE'd from Lg/a0/c/e0/j3/k;->e) ----
const SIGN_SALT = "rDJiNB9j7vD2";
const SIGN_SALT_W7 = "eFoqdHOdDy6ViJ0i";
const AES_KEY = "goMEzJ1pDpncNHb9";
const AES_IV = "ZUrAS2lUidjyY2gK";
const W7 = ["Login/quickLoginV339", "Login/RefreshToken", "Run2/beforeRunV260", "Run/stopRunV278",
  "Run2/gyroscope", "Run/setRunLocationRecord", "Report/getOssSign", "report/getOssSts"];
const V7 = ["Login/quickLoginV339"];
const TARGET_VN = process.env.TARGET_VN || "4.3.0";
const REWRITE_VERSION = process.env.REWRITE_VERSION || "233";
const RSP_KEY = process.env.RSP_KEY || "Wet2C8d34f62ndi3";
const RSP_IV = process.env.RSP_IV || "K6iv85jBD8jgf32D";
const LIE_VERSION = process.env.LIE_VERSION || "220";
const LIE_VN = process.env.LIE_VN || "4.2.0";

function cmpVer(a, b) {
  const pa = String(a).split(".").map(n => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function verFix(vn, vc) {
  const vnLow = typeof vn === "string" && cmpVer(vn, TARGET_VN) < 0;
  const n = vc == null ? NaN : parseInt(vc, 10);
  const vcLow = isFinite(n) && n < parseInt(REWRITE_VERSION, 10);
  return { vnLow, vcLow };
}
const SKIP_V7 = ["nick_name", "avatar_url"];
// Form-decode one body value. The client concatenates "k+v" from its in-memory
// map and URL-encodes only for transport; the server (PHP $_POST) decodes before
// it re-signs. So the sign input always uses the DECODED value. Leaving "%2C" in
// the input is what made Run/getTimestampV278 (point_ids=<点位列表>) and
// Report/appLog (fileName=Public/Upload/...) come back as {"status":0,"info":"非法请求"}.
// Values produced by java.net.URLEncoder encode a literal "+" as "%2B", so a bare
// "+" in the body can only be a space.
function formDecode(s) {
  const t = String(s);
  if (t.indexOf("%") < 0 && t.indexOf("+") < 0) return t;
  try { return decodeURIComponent(t.replace(/\+/g, " ")); } catch { return t; }
}
function signFor(obj, prefixMode, v7 = false) {
  const ks = Object.keys(obj).filter(k => k !== "sign" && k !== "file"
    && !(prefixMode && k === "mobileDeviceId")
    && !(v7 && SKIP_V7.includes(k))).sort();
  const body = ks.map(k => k + obj[k]).join("");
  const s = prefixMode ? SIGN_SALT_W7 + body : body + SIGN_SALT;
  return crypto.createHash("md5").update(s, "utf8").digest("hex");
}
function aesDecrypt(text) {
  const b64 = decodeURIComponent(text).replace(/\s+/g, "");
  const d = crypto.createDecipheriv("aes-128-cbc", Buffer.from(AES_KEY, "utf8"), Buffer.from(AES_IV, "utf8"));
  return Buffer.concat([d.update(Buffer.from(b64, "base64")), d.final()]).toString("utf8");
}
function aesEncrypt(plain) {
  const c = crypto.createCipheriv("aes-128-cbc", Buffer.from(AES_KEY, "utf8"), Buffer.from(AES_IV, "utf8"));
  const out = Buffer.concat([c.update(Buffer.from(plain, "utf8")), c.final()]).toString("base64");
  const wrapped = out.replace(/(.{76})/g, "$1\n") + "\n";
  return encodeURIComponent(wrapped);
}
function rspDecrypt(b64) {
  const s = String(b64).replace(/\s+/g, "");
  const d = crypto.createDecipheriv("aes-128-cbc", Buffer.from(RSP_KEY, "utf8"), Buffer.from(RSP_IV, "utf8"));
  return Buffer.concat([d.update(Buffer.from(s, "base64")), d.final()]).toString("utf8");
}
function rspEncrypt(plain) {
  const c = crypto.createCipheriv("aes-128-cbc", Buffer.from(RSP_KEY, "utf8"), Buffer.from(RSP_IV, "utf8"));
  return Buffer.concat([c.update(Buffer.from(plain, "utf8")), c.final()]).toString("base64");
}
function rewriteUpdateResponse(p, buf) {
  if (!/system\/update/i.test(String(p))) return null;
  let obj;
  try { obj = JSON.parse(buf.toString("utf8")); } catch { return null; }
  if (!obj || typeof obj.data !== "string" || !obj.is_encrypt) return null;
  let info;
  try { info = JSON.parse(rspDecrypt(obj.data)); } catch { return null; }
  const before = {
    max_version: info.max_version, min_version: info.min_version,
    versionCode: info.versionCode, versionNumber: info.versionNumber, url: info.url,
  };
  info.max_version = LIE_VERSION;
  info.min_version = LIE_VERSION;
  info.versionCode = LIE_VERSION;
  info.versionNumber = LIE_VN;
  info.versionName = "";
  info.url = "";
  obj.data = rspEncrypt(JSON.stringify(info));
  const after = {
    max_version: info.max_version, min_version: info.min_version,
    versionCode: info.versionCode, versionNumber: info.versionNumber, url: info.url,
  };
  return { body: Buffer.from(JSON.stringify(obj, null, 4), "utf8"), before, after };
}
function resignBody(txt, p) {
  if (/^key=/.test(txt)) {
    let obj;
    try { obj = JSON.parse(aesDecrypt(txt.slice(4))); } catch { return null; }
    if (!obj || typeof obj !== "object") return null;
    const f = verFix(obj.version_name, obj.version);
    if (!f.vnLow && !f.vcLow) return null;
    if (f.vnLow) obj.version_name = TARGET_VN;
    if (f.vcLow) obj.version = (typeof obj.version === "number" ? parseInt(REWRITE_VERSION, 10) : REWRITE_VERSION);
    const prefixMode = W7.some(s => p.includes(s));
    obj.sign = signFor(obj, prefixMode, V7.some(s => p.includes(s)));
    return {
      body: "key=" + aesEncrypt(JSON.stringify(obj)), sign: obj.sign, prefixMode, enc: true,
      vn: f.vnLow ? TARGET_VN : obj.version_name, vc: f.vcLow ? REWRITE_VERSION : obj.version,
    };
  }
  const pairs = txt.split("&").filter(Boolean).map(s => {
    const i = s.indexOf("=");
    return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)];
  });
  const vi = pairs.findIndex(q => q[0] === "version_name");
  const ci = pairs.findIndex(q => q[0] === "version");
  if (vi < 0 && ci < 0) return null;
  const f = verFix(vi >= 0 ? pairs[vi][1] : undefined, ci >= 0 ? pairs[ci][1] : undefined);
  if (!f.vnLow && !f.vcLow) return null;
  if (f.vnLow) pairs[vi][1] = TARGET_VN;
  if (f.vcLow) pairs[ci][1] = REWRITE_VERSION;
  const prefixMode = W7.some(s => p.includes(s));
  // sign input uses form-decoded keys/values (see formDecode); the wire body below
  // keeps the original encoded form.
  const obj = {};
  for (const [k, v] of pairs) obj[formDecode(k)] = formDecode(v);
  const sign = signFor(obj, prefixMode, V7.some(s => p.includes(s)));
  const si = pairs.findIndex(q => q[0] === "sign");
  if (si >= 0) pairs[si][1] = sign; else pairs.push(["sign", sign]);
  return {
    body: pairs.map(([k, v]) => k + "=" + v).join("&"), sign, prefixMode, enc: false,
    vn: f.vnLow ? TARGET_VN : (vi >= 0 ? pairs[vi][1] : ""),
    vc: f.vcLow ? REWRITE_VERSION : (ci >= 0 ? pairs[ci][1] : ""),
  };
}

// ---------------- config ----------------
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || "8888", 10);
const BIND = process.env.BIND || "127.0.0.1";
const LOG = process.env.LOG || path.join(HERE, "capture.jsonl");
// NOTE: proxy.out.log is rotated by common.sh (copytruncate) because this
// process's stdout is opened by the shell (`>>`). Renaming that file from here
// would strand the shell's fd in the rotated inode, so the "new" log would stay
// empty forever while the rotated copy kept growing. We only rotate our own
// fd (capture.jsonl) below.
const OUTLOG = path.join(HERE, "proxy.out.log");
// 8 MiB keeps weeks of normal running traffic on /data without ever filling it.
const MAX_LOG = 8 * 1024 * 1024;
const MAX_CAPTURE = parseInt(process.env.MAX_CAPTURE || "", 10) || MAX_LOG;

// hosts whose TLS we terminate + rewrite. everything else is passthrough.
const INTERCEPT_RE = process.env.INTERCEPT_RE
  ? new RegExp(process.env.INTERCEPT_RE, "i")
  : /^(api2|api|pre-api)\.lptiyu\.com$/i;

// Pinned upstream IPs, written by service.sh / tanke-proxy.sh (avoids the flaky
// getaddrinfo() that a root process on Android exhibits: ENOTFOUND on ~10% of
// lookups, which v1 logged as `[ERR] api2.lptiyu.com ... getaddrinfo ENOTFOUND`).
function loadTargets() {
  const out = new Map();
  const f = process.env.TARGETS_FILE || path.join(HERE, "targets.env");
  try {
    for (const ln of fs.readFileSync(f, "utf8").split("\n")) {
      const m = /^\s*([A-Za-z0-9_.\-]+)\s*=\s*([0-9.,\s]+)\s*$/.exec(ln);
      if (!m) continue;
      const ips = m[2].split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
      if (ips.length) out.set(m[1].toLowerCase(), ips);
    }
  } catch { /* no pin file: fall back to DNS */ }
  return out;
}
let TARGETS = loadTargets();
setInterval(() => {
  // pick up IP refreshes done by the watchdog without a restart
  try {
    const nxt = loadTargets();
    if (nxt.size) TARGETS = nxt;
  } catch { }
}, 60_000).unref();

const NS_CANDIDATES = (process.env.DNS_SERVERS || "192.168.1.1,114.114.114.114,223.5.5.5")
  .split(",").map(s => s.trim()).filter(Boolean);

// ---------------- minimal DNS A resolver (bypasses bionic/netd for root) ----------------
const dnsCache = new Map(); // host -> { ips, exp }

function buildQuery(host) {
  const labels = host.split(".").filter(Boolean);
  const parts = [];
  const id = crypto.randomInt(0, 0xffff);
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2); // RD
  head.writeUInt16BE(1, 4);      // QDCOUNT
  parts.push(head);
  for (const l of labels) {
    const b = Buffer.from(l, "ascii");
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  const q = Buffer.alloc(4);
  q.writeUInt16BE(1, 0); // A
  q.writeUInt16BE(1, 2); // IN
  parts.push(q);
  return { id, packet: Buffer.concat(parts) };
}

function parseAnswers(buf, wantId) {
  if (buf.length < 12) return null;
  if (buf.readUInt16BE(0) !== wantId) return null;
  const flags = buf.readUInt16BE(2);
  if ((flags & 0x000f) !== 0) return null;      // rcode != NOERROR
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let p = 12;
  for (let i = 0; i < qd; i++) {
    while (p < buf.length) {
      const l = buf[p];
      if (l === 0) { p += 1; break; }
      if ((l & 0xc0) === 0xc0) { p += 2; break; }
      p += 1 + l;
    }
    p += 4;
  }
  const ips = [];
  for (let i = 0; i < an && p + 10 <= buf.length; i++) {
    // name (possibly compressed)
    if ((buf[p] & 0xc0) === 0xc0) p += 2;
    else { while (p < buf.length && buf[p] !== 0) p += 1 + buf[p]; p += 1; }
    if (p + 10 > buf.length) break;
    const type = buf.readUInt16BE(p);
    const rdlen = buf.readUInt16BE(p + 8);
    p += 10;
    if (type === 1 && rdlen === 4) ips.push(`${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`);
    p += rdlen;
  }
  return ips;
}

function udpResolve(ns, host, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    let done = false;
    const fin = (v) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch { }
      resolve(v);
    };
    const t = setTimeout(() => fin([]), timeoutMs);
    t.unref?.();
    sock.on("error", () => fin([]));
    sock.on("message", (msg) => {
      const { id } = q;
      const ips = parseAnswers(msg, id);
      fin(ips || []);
    });
    const q = buildQuery(host);
    try { sock.send(q.packet, 53, ns); } catch { fin([]); }
  });
}

async function resolveHost(host) {
  const key = host.toLowerCase();
  const hit = dnsCache.get(key);
  if (hit && hit.exp > Date.now()) return hit.ips;
  for (const ns of NS_CANDIDATES) {
    const ips = await udpResolve(ns, key);
    if (ips.length) {
      dnsCache.set(key, { ips, exp: Date.now() + 600_000 });
      return ips;
    }
  }
  // last resort: libc resolver (flaky as root, but better than nothing)
  const viaLibc = await new Promise((res) => {
    const dns = require0();
    dns.lookup(key, { all: true, family: 4 }, (e, addrs) => {
      if (e || !addrs || !addrs.length) return res([]);
      res(addrs.map(a => a.address));
    });
  });
  if (viaLibc.length) {
    dnsCache.set(key, { ips: viaLibc, exp: Date.now() + 300_000 });
    return viaLibc;
  }
  if (hit) return hit.ips; // stale is better than nothing
  return [];
}
// tiny indirection so the ESM import of node:dns stays cheap
let _dns = null;
function require0() {
  if (!_dns) _dns = globalThis.__nodeDns;
  return _dns;
}

const upstreamIPs = (host) => TARGETS.get(host.toLowerCase()) || null;

// ---------------- CA / leaf certificates ----------------
// NO runtime certificate signing and NO third-party crypto library.
//
// The intercept set is fixed and tiny (INTERCEPT_RE, three hosts), so a leaf for
// every host is minted ONCE at deploy time by gencert.mjs (pure node:crypto,
// hand-rolled DER) and this process only reads the files back. That is what
// removes the node-forge / node_modules dependency: there is no keygen and no
// ASN.1 work left in the hot path at all.
//
// Files (all under CERT_DIR, defaulting to this script's directory):
//   ca.crt.pem                        root CA the device already trusts
//   ca.key.pem                        its key (only needed by gencert, not here)
//   leafs/<host>.crt.pem              leaf certificate
//   leafs/<host>.key.pem              matching private key
//
// A missing leaf is NOT fatal and NOT silent: the host is logged as LEAF_MISS and
// that connection is passed through untouched (the app still reaches the real
// server, it just gets the unmodified version gate back). `tanke-proxy.sh
// selftest` fails when any intercept host has no leaf, so this cannot rot unseen.
const CERT_DIR = process.env.CERT_DIR || HERE;
const caCertPath = path.join(CERT_DIR, "ca.crt.pem");
const caKeyPath = path.join(CERT_DIR, "ca.key.pem");
const LEAF_DIR = process.env.LEAF_DIR || path.join(CERT_DIR, "leafs");

const leaves = new Map();

function loadLeaves() {
  let names = [];
  try {
    names = fs.readdirSync(LEAF_DIR).filter((n) => n.endsWith(".crt.pem"));
  } catch {
    return;
  }
  for (const n of names) {
    const host = n.slice(0, -".crt.pem".length).toLowerCase();
    const crt = path.join(LEAF_DIR, host + ".crt.pem");
    const key = path.join(LEAF_DIR, host + ".key.pem");
    try {
      const cert = fs.readFileSync(crt, "utf8");
      const priv = fs.readFileSync(key, "utf8");
      // createSecureContext parses both and rejects a cert/key mismatch, so a
      // half-copied deploy shows up here at startup instead of as TLS errors.
      tls.createSecureContext({ key: priv, cert, minVersion: "TLSv1.2" });
      leaves.set(host, { host, cert, key: priv });
    } catch (e) {
      console.log(`[leaf] ${host}: unusable (${e.message}) -> not intercepting it`);
    }
  }
}
loadLeaves();

function leafFor(host) {
  return leaves.get(String(host || "").toLowerCase()) || null;
}
// Only intercept hosts we actually hold a certificate for; everything else is
// byte-for-byte passthrough (see startPassthrough).
function wantsIntercept(host) {
  return !!host && INTERCEPT_RE.test(host) && !!leafFor(host);
}

// ---------------- logging ----------------
// Rotate the log WE own (capture.jsonl): close the stream, move the file aside,
// reopen. proxy.out.log is deliberately left to common.sh (copytruncate) - see
// the note next to OUTLOG above.
let logStream = fs.createWriteStream(LOG, { flags: "a" });
let logBytes = 0;
try { logBytes = fs.statSync(LOG).size; } catch { }
function rotateCapture() {
  try {
    // Measure the FILE, not just this process's write counter: the counter
    // drifts from reality (and misses anything appended by hand or by a
    // previous process image), so rotation used to never fire in tests.
    let size = 0;
    try { size = fs.statSync(LOG).size; } catch { return; }
    logBytes = size;
    if (size < MAX_CAPTURE) return;
    // Move the file FIRST; if that cannot succeed there is nothing to reopen and
    // repeatedly closing/creating the stream would just churn on every rec().
    try {
      fs.renameSync(LOG, LOG + ".1");
    } catch {
      try { fs.unlinkSync(LOG + ".1"); } catch { }
      try { fs.renameSync(LOG, LOG + ".1"); } catch { return; }
    }
    try { logStream.end(); } catch { }
    logStream = fs.createWriteStream(LOG, { flags: "a" });
    logBytes = 0;
    const brief = `[LOG_ROTATE] capture.jsonl -> .1 (${MAX_CAPTURE} bytes)`;
    try { logStream.write(JSON.stringify({ kind: "LOG_ROTATE", note: brief, ts: new Date().toISOString() }) + "\n"); } catch { }
    console.log(brief);
  } catch (e) {
    try { console.log("[LOG_ROTATE_FAIL] " + e.message); } catch { }
  }
}
// time-driven so rotation keeps happening without any other caller
setInterval(rotateCapture, 60_000).unref();
function rec(obj) {
  obj.ts = new Date().toISOString();
  const line = JSON.stringify(obj) + "\n";
  try { logStream.write(line); logBytes += line.length; } catch { }
  rotateCapture();
  const brief = `[${obj.kind}] ${obj.host || ""} ${obj.path || ""} ${obj.status || ""} ${obj.note || ""}`;
  console.log(brief);
}

// ---------------- ClientHello SNI ----------------
function peekSNI(buf) {
  if (buf.length < 6) return { state: "need-more" };
  if (buf[0] !== 0x16) return { state: "not-tls" };
  if (buf.length < 5) return { state: "need-more" };
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return { state: "need-more" };
  let p = 5;
  if (buf[p] !== 0x01) return { state: "not-clienthello" };
  p += 4;
  if (p + 2 + 32 > buf.length) return { state: "need-more" };
  p += 2 + 32;
  const sidLen = buf[p]; p += 1 + sidLen;
  if (p + 2 > buf.length) return { state: "need-more" };
  const csLen = buf.readUInt16BE(p); p += 2 + csLen;
  if (p + 1 > buf.length) return { state: "need-more" };
  const cmLen = buf[p]; p += 1 + cmLen;
  if (p + 2 > buf.length) return { state: "need-more" };
  const extTotal = buf.readUInt16BE(p); p += 2;
  const end = Math.min(p + extTotal, buf.length);
  while (p + 4 <= end) {
    const et = buf.readUInt16BE(p);
    const el = buf.readUInt16BE(p + 2);
    p += 4;
    if (et === 0) {
      let q = p + 2;
      const listEnd = Math.min(p + el, buf.length);
      while (q + 3 <= listEnd) {
        const nt = buf[q];
        const nl = buf.readUInt16BE(q + 1);
        q += 3;
        if (nt === 0) return { state: "ok", sni: buf.slice(q, q + nl).toString("ascii") };
        q += nl;
      }
    }
    p += el;
  }
  return { state: "no-sni" };
}

// ---------------- HTTP over an established stream ----------------
function parseHeaders(text) {
  const lines = text.split("\r\n");
  const first = lines.shift() || "";
  const headers = [];
  for (const ln of lines) {
    if (!ln) continue;
    const i = ln.indexOf(":");
    if (i < 0) continue;
    headers.push([ln.slice(0, i).trim(), ln.slice(i + 1).trim()]);
  }
  return { first, headers };
}

function dechunk(buf) {
  let out = Buffer.alloc(0);
  let off = 0;
  while (off < buf.length) {
    const nl = buf.indexOf("\r\n", off);
    if (nl < 0) break;
    const sizeStr = buf.slice(off, nl).toString("ascii").split(";")[0].trim();
    const size = parseInt(sizeStr, 16);
    if (!isFinite(size) || size < 0) break;
    off = nl + 2;
    if (size === 0) break;
    out = Buffer.concat([out, buf.slice(off, off + size)]);
    off += size + 2;
  }
  return out;
}

function tryDecrypt(buf) {
  if (!buf || !buf.length) return null;
  const cands = [
    ["K6iv85jBD8jgf32D", "goMEzJ1pDpncNHb9", "params_new_game"],
    ["Wet2C8d34f62ndi3", "J98huiy7EWF78S4a", "app_key"],
  ];
  for (const [k, iv, tag] of cands) {
    for (const enc of ["base64", "raw"]) {
      let data;
      if (enc === "base64") {
        const s = buf.toString("utf8").trim();
        if (!/^[A-Za-z0-9+/=\s]+$/.test(s)) continue;
        try { data = Buffer.from(s, "base64"); } catch { continue; }
        if (!data.length) continue;
      } else {
        data = buf;
      }
      try {
        const d = crypto.createDecipheriv("aes-128-cbc", Buffer.from(k, "utf8"), Buffer.from(iv, "utf8"));
        const out = Buffer.concat([d.update(data), d.final()]);
        const t = out.toString("utf8");
        if (/^[\x09\x0a\x0d\x20-\x7e\u4e00-\u9fff]+\s*$/.test(t) && /[{\[]/.test(t)) {
          return { tag, enc, text: t };
        }
      } catch { }
    }
  }
  return null;
}

function serveHttp(stream, isTls, sni, fallbackHost, fallbackPort) {
  let buf = Buffer.alloc(0);
  let busy = false;

  // Hard idle cap per client connection. Without it a client that never closes
  // its half keeps an fd forever: a 200-connection burst during the robustness
  // tests pinned 128 fds (== maxConnections) and they never came back.
  try {
    stream.setTimeout(30_000, () => { try { stream.destroy(); } catch { } });
  } catch { }

  async function pump() {
    if (busy) return;
    busy = true;
    try {
      for (;;) {
        const hdrEnd = buf.indexOf("\r\n\r\n");
        if (hdrEnd < 0) break;
        const headText = buf.slice(0, hdrEnd).toString("utf8");
        const { first, headers } = parseHeaders(headText);
        const [method, target, ver] = first.split(" ");
        const hmap = {};
        for (const [k, v] of headers) hmap[k.toLowerCase()] = v;
        const bodyLen = parseInt(hmap["content-length"] || "0", 10);
        const chunked = (hmap["transfer-encoding"] || "").toLowerCase().includes("chunked");
        const bodyOff = hdrEnd + 4;
        if (chunked) {
          const rest = buf.slice(bodyOff);
          const endIdx = rest.indexOf("0\r\n\r\n");
          if (endIdx < 0) break;
          buf = buf.slice(bodyOff + endIdx + 5);
          const reqBody = dechunk(rest.slice(0, endIdx + 5));
          await handle(method, target, hmap, reqBody, ver);
          continue;
        }
        if (buf.length < bodyOff + bodyLen) break;
        const reqBody = buf.slice(bodyOff, bodyOff + bodyLen);
        buf = buf.slice(bodyOff + bodyLen);
        await handle(method, target, hmap, reqBody, ver);
      }
    } finally {
      busy = false;
    }
  }

  async function handle(method, target, hmap, reqBody, ver) {
    const hostHeader = (hmap["host"] || "").split(":")[0];
    const host = (sni || hostHeader || fallbackHost || "").toLowerCase();
    const p = target || "/";
    const dec = tryDecrypt(reqBody);
    // v2.3.1: 给「版本适配探测器」留一条低损耗的兜底。
    // bodyText 在 body >= 20000 字节时整个不写、> 8000 字符时被截断，而 sign 一般
    // 排在表单最后 —— 一截断就正好把最关键的字段切掉，adapt-probe 就无法验证该端点。
    // 所以只在「bodyText 丢信息」的时候，额外记一段尾巴（≤600 字符）。正常情况下不写，
    // 日志体积不受影响。
    const bodyStr = reqBody.length && reqBody.length < 100000 ? reqBody.toString("utf8") : "";
    const bodyLost = reqBody.length > 0 && (!bodyStr || bodyStr.length > 8000);
    rec({
      kind: "REQ", host, path: p, method, tls: isTls, sni: sni || null,
      bodyLen: reqBody.length,
      bodyText: reqBody.length && reqBody.length < 20000 ? bodyStr.slice(0, 8000) : undefined,
      signTail: bodyLost ? bodyStr.slice(-600) : undefined,
      decrypted: dec ? dec.text.slice(0, 20000) : null,
      decryptTag: dec ? dec.tag + "/" + dec.enc : null,
    });

    const upstreamHeaders = { ...hmap };
    delete upstreamHeaders["proxy-connection"];
    delete upstreamHeaders["accept-encoding"]; // avoid gzip
    upstreamHeaders["host"] = hostHeader || host;

    // ---- version-gate bypass ----
    let outBody = reqBody;
    if (reqBody.length) {
      try {
        const rw = resignBody(reqBody.toString("utf8"), p);
        if (rw) {
          outBody = Buffer.from(rw.body, "utf8");
          upstreamHeaders["content-length"] = String(outBody.length);
          rec({
            kind: "REWRITE", host, path: p, sign: rw.sign, prefixMode: rw.prefixMode,
            // 400 太短：加密体 key=... 有 700+ 字符，一截就成半截密文，事后无法复核。
            // 放到 3000，加密体也能完整留档（sign 规则变化时全靠这段做 A/B）。
            vn: rw.vn, vc: rw.vc, enc: rw.enc === true,
            fromLen: reqBody.length, toLen: rw.body.length,
            from: reqBody.toString("utf8").slice(0, 3000), to: rw.body.slice(0, 3000),
          });
        }
      } catch (e) { rec({ kind: "REWRITE_ERR", path: p, note: String(e && e.message) }); }
    }

    const t0 = Date.now();
    const result = await requestUpstream({ host, method, path: p, headers: upstreamHeaders, body: outBody, isTls });

    if (result.error) {
      rec({ kind: "ERR", host, path: p, note: result.error.message });
      try { stream.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); } catch { }
      try {
        if (typeof stream.destroySoon === "function") stream.destroySoon();
        else stream.end();
      } catch { }
      return;
    }

    let { res, body } = result;
    try {
      const rw2 = rewriteUpdateResponse(p, body);
      if (rw2) {
        body = rw2.body;
        rec({ kind: "REWRITE_RSP", host, path: p, before: rw2.before, after: rw2.after, note: "update-check -> up-to-date" });
      }
    } catch (e) { rec({ kind: "REWRITE_RSP_ERR", path: p, note: String(e && e.message) }); }

    const rdec = tryDecrypt(body);
    rec({
      kind: "RSP", host, path: p, status: res.statusCode, ms: Date.now() - t0,
      bodyLen: body.length,
      bodyText: body.length && body.length < 20000 ? body.toString("utf8").slice(0, 8000) : undefined,
      decrypted: rdec ? rdec.text.slice(0, 30000) : null,
      decryptTag: rdec ? rdec.tag + "/" + rdec.enc : null,
    });

    const outHeaders = [];
    for (const [k, v] of Object.entries(res.headers)) {
      if (["transfer-encoding", "connection", "content-encoding", "content-length"].includes(k.toLowerCase())) continue;
      if (Array.isArray(v)) v.forEach(vv => outHeaders.push([k, vv]));
      else outHeaders.push([k, v]);
    }
    outHeaders.push(["Content-Length", String(body.length)]);
    outHeaders.push(["Connection", "close"]);
    let head = `HTTP/1.1 ${res.statusCode} ${res.statusMessage || "OK"}\r\n`;
    for (const [k, v] of outHeaders) head += `${k}: ${v}\r\n`;
    head += "\r\n";
    try {
      stream.write(head);
      stream.write(body);
      // Connection: close was already sent, so do not linger waiting for the
      // peer's FIN - destroySoon() flushes then tears the socket down.
      if (typeof stream.destroySoon === "function") stream.destroySoon();
      else { stream.end(); setTimeout(() => { try { stream.destroy(); } catch { } }, 2_000).unref?.(); }
    } catch { }
  }

  stream.on("data", (d) => { buf = Buffer.concat([buf, d]); pump(); });
  stream.on("error", () => { });
  stream.on("close", () => { });
  pump();
}

// One upstream request with pinned-IP failover, then DNS fallback.
async function requestUpstream({ host, method, path: p, headers, body, isTls }) {
  const pinned = upstreamIPs(host);
  const candidates = [];
  if (pinned) for (const ip of pinned) candidates.push(ip);
  const attempts = candidates.length ? [...candidates, null] : [null]; // null = resolve normally
  let lastErr = null;

  for (const ip of attempts) {
    let addr = ip;
    if (!addr) {
      const ips = await resolveHost(host);
      if (!ips.length) { lastErr = new Error(`ENOTFOUND ${host}`); continue; }
      addr = ips[0];
    }
    const r = await new Promise((resolve) => {
      const lib = isTls ? https : http;
      const opts = {
        host: addr,
        port: isTls ? 443 : 80,
        path: p,
        method,
        headers,
        agent: false,
        rejectUnauthorized: false,
      };
      if (isTls) opts.servername = host; // SNI + Host validation against the real name
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ res, body: Buffer.concat(chunks) }));
        res.on("error", (e) => resolve({ error: e }));
      });
      req.on("error", (e) => resolve({ error: e }));
      req.setTimeout(20000, () => req.destroy(new Error("timeout")));
      if (body && body.length) req.write(body);
      req.end();
    });
    if (!r.error) return r;
    lastErr = r.error;
  }
  return { error: lastErr || new Error("no-route") };
}

// ---------------- TLS handling ----------------
function startMitm(client, sni) {
  const host = sni;
  const leaf = leafFor(host);
  if (!leaf) {
    // wantsIntercept() gates every call site, so this is a "should never happen"
    // that still fails safe: no bogus cert, just pass the connection through.
    rec({ kind: "LEAF_MISS", host, note: "no leaf cert -> passthrough" });
    try { client.destroy(); } catch { }
    return;
  }
  const tlsSock = new tls.TLSSocket(client, {
    isServer: true,
    key: leaf.key,
    cert: leaf.cert,
    ALPNProtocols: ["http/1.1"],
  });
  tlsSock.on("error", (e) => rec({ kind: "TLSERR", host, note: e.message }));
  tlsSock.on("secure", () => rec({ kind: "TLS_OK", host, alpn: tlsSock.alpnProtocol || "" }));
  serveHttp(tlsSock, true, host);
}

function startPassthrough(client, firstBuf, sni) {
  const host = sni;
  (async () => {
    let ips = upstreamIPs(host) || [];
    if (!ips.length) ips = await resolveHost(host);
    if (!ips.length) {
      rec({ kind: "PASS_ERR", host, note: "no ip" });
      try { client.destroy(); } catch { }
      return;
    }
    // Listeners for "the client went away" are registered ONCE. Attaching them
    // inside tryIp() leaked one error+close pair per upstream candidate every
    // time a host had several A records.
    let up = null;
    const onClientGone = () => { try { up && up.destroy(); } catch { } };
    client.on("error", onClientGone);
    client.on("close", onClientGone);
    const tryIp = (i) => {
      if (i >= ips.length) {
        rec({ kind: "PASS_ERR", host, note: "all ips failed" });
        try { client.destroy(); } catch { }
        return;
      }
      up = net.connect(443, ips[i], () => {
        rec({ kind: "PASS", host, ip: ips[i] });
        up.write(firstBuf);          // replay the exact ClientHello bytes
        client.pipe(up);
        up.pipe(client);
      });
      up.on("error", () => { try { up.destroy(); } catch { } tryIp(i + 1); });
      up.setTimeout(30000, () => { try { up.destroy(); } catch { } });
    };
    tryIp(0);
  })();
}

// ---------------- server ----------------
// Bound concurrent connections: a pile-up of stuck clients must not exhaust the
// process fd table. Idle baseline on this device: 20 fds / 11 threads.
const MAX_CONNS = parseInt(process.env.MAX_CONNS || "", 10) || 128;
const server = net.createServer((client) => {
  client.on("error", () => { });
  let buf = Buffer.alloc(0);
  let settled = false;

  // hand the socket to a consumer. "unshift" puts already-read bytes back so the
  // next consumer (TLS layer / HTTP parser) sees them; "none" means the caller
  // already forwarded those bytes upstream and must not see them twice.
  const finish = (mode, fn) => {
    settled = true;
    client.removeListener("data", onData);
    if (mode === "unshift") {
      try { client.pause(); } catch { }
      try { client.unshift(buf); } catch { }
    }
    fn();
  };

  const onData = (chunk) => {
    if (settled) return;
    buf = Buffer.concat([buf, chunk]);

    // 1) legacy CONNECT proxy request
    const nl = buf.indexOf("\r\n");
    if (buf.length >= 8) {
      const head = buf.slice(0, 64).toString("latin1");
      if (/^CONNECT\s/i.test(head)) {
        if (nl < 0) return; // wait for the request line
        const line = buf.slice(0, nl).toString("latin1");
        const m = /^CONNECT\s+([^\s:]+):(\d+)/i.exec(line);
        if (!m) { finished(); return; }
        const host = m[1];
        const port = parseInt(m[2], 10);
        const doIntercept = wantsIntercept(host);
        rec({ kind: "CONNECT", host, port, intercept: doIntercept });
        // drop the CONNECT header, keep any pipelined payload
        const rest = buf.slice(nl + 2);
        const hdrEnd = rest.indexOf("\r\n\r\n");
        const payload = hdrEnd >= 0 ? rest.slice(hdrEnd + 4) : Buffer.alloc(0);
        settled = true;
        client.removeListener("data", onData);
        try { client.write("HTTP/1.1 200 Connection Established\r\n\r\n"); } catch { }
        if (payload.length) { try { client.unshift(payload); } catch { } }
        if (doIntercept) {
          startMitm(client, host);
        } else {
          const up = net.connect(port, host, () => { up.pipe(client); client.pipe(up); });
          up.on("error", () => { try { client.end(); } catch { } });
          client.on("error", () => { try { up.end(); } catch { } });
          client.on("close", () => { try { up.end(); } catch { } });
        }
        return;
      }
    }

    // 2) TLS
    if (buf[0] === 0x16) {
      const r = peekSNI(buf);
      if (r.state === "need-more") return;
      if (r.state === "ok") {
        const sni = r.sni;
        const doIntercept = wantsIntercept(sni);
        rec({ kind: "TLS", sni, intercept: doIntercept });
        if (!doIntercept && INTERCEPT_RE.test(sni)) rec({ kind: "LEAF_MISS", host: sni });
        if (doIntercept) finish("unshift", () => startMitm(client, sni));
        else finish("none", () => startPassthrough(client, buf, sni));
        return;
      }
      // no SNI (rare: IP-literal connections). If an intercept host was expected,
      // fall back to the configured default; otherwise pass through blindly.
      if (r.state === "no-sni") {
        const def = process.env.DEFAULT_SNI || "";
        if (wantsIntercept(def)) {
          rec({ kind: "TLS_NOSNI", fallback: def });
          finish("unshift", () => startMitm(client, def));
        } else {
          rec({ kind: "TLS_NOSNI", note: "drop" });
          try { client.destroy(); } catch { }
        }
        return;
      }
      if (r.state === "not-clienthello") {
        rec({ kind: "TLS_OTHER", note: "non-clienthello first record" });
        try { client.destroy(); } catch { }
        return;
      }
      return;
    }

    // 3) plain HTTP
    if (nl >= 0) {
      const line = buf.slice(0, nl).toString("latin1");
      rec({ kind: "PLAIN", note: line.slice(0, 120) });
      finish("unshift", () => serveHttp(client, false, null, "127.0.0.1", 80));
    }
  };
  function finished() { settled = true; client.removeListener("data", onData); try { client.destroy(); } catch { } }

  client.on("data", onData);
});
server.maxConnections = MAX_CONNS;

// ---------------- heartbeat ----------------
// A live listener is not proof of a live proxy: an exhausted or wedged process
// can still hold the socket while serving nothing. The watchdog therefore also
// checks that this timestamp keeps moving. utimes() is used instead of rewriting
// the file so the cost stays negligible.
const HEARTBEAT = process.env.HEARTBEAT || path.join(HERE, ".heartbeat");
function beat() {
  try {
    const t = new Date();
    try { fs.utimesSync(HEARTBEAT, t, t); } catch { fs.writeFileSync(HEARTBEAT, String(t.getTime())); }
  } catch { }
}
beat();
setInterval(beat, 30_000).unref();

(async () => {
  globalThis.__nodeDns = (await import("node:dns"));
  server.listen(PORT, BIND, () => {
    const pinned = [...TARGETS.entries()].map(([h, ips]) => `${h}=${ips.join(",")}`).join(" ");
    console.log(`mitm v2 (transparent) listening on ${BIND}:${PORT} log=${LOG}`);
    console.log(`maxConns=${MAX_CONNS} captureCap=${MAX_CAPTURE} logBytes=${logBytes}`);
    console.log(`intercept=${INTERCEPT_RE} targets=[${pinned}]`);
    console.log(`CA=${caCertPath}`);
    console.log(`leafs=${[...leaves.keys()].join(",") || "(none)"} dir=${LEAF_DIR}`);
    rec({ kind: "START", note: `port=${PORT} bind=${BIND} targets=${pinned}` });
    if (!leaves.size) {
      // Not a crash: passthrough still works, but nothing gets rewritten until
      // `tanke-proxy.sh` has run the deploy-time certificate step.
      console.log("[warn] no leaf certificates found - every host will be passed through");
      rec({ kind: "LEAF_MISS", note: `no leafs in ${LEAF_DIR}` });
    }
  });
})();

// Signals this module never uses must not be able to kill the proxy. Node turns
// SIGUSR1/SIGUSR2 into debugger actions and exits when it cannot satisfy them -
// an accidental `kill -USR2` used to take the proxy down for a whole watchdog
// tick. SIGTERM deliberately stays at its default so stop_proxy still works.
for (const sig of ["SIGUSR1", "SIGUSR2", "SIGHUP"]) {
  try { process.on(sig, () => { }); } catch { }
}

// A process that only LOGS its crashes can survive in a half-broken state while
// still holding the listening socket - the watchdog would then see it as
// healthy and never restart it. After a burst of fatal errors, exit on purpose
// so the watchdog brings up a clean process. A single isolated error (one bad
// client socket) stays non-fatal.
let fatalCount = 0;
const onFatal = (kind) => (e) => {
  fatalCount++;
  rec({ kind, note: String((e && e.stack) || e), fatalCount });
  if (fatalCount >= 5) {
    try { console.log("[FATAL_EXIT] too many fatal errors, exiting for a clean restart"); } catch { }
    process.exit(1);
  }
};
process.on("uncaughtException", onFatal("FATAL"));
process.on("unhandledRejection", onFatal("FATAL_REJ"));
