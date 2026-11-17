// Standalone A-record resolver for the Magisk boot script.
// Uses direct UDP queries instead of getaddrinfo(), because a root process on
// this device intermittently fails libc DNS (`getaddrinfo ENOTFOUND`) — that
// exact failure was observed 21x in the v1 proxy log and is what made upstream
// requests sporadically die.
//
// usage: node resolve4.mjs <host> [host...] [--ns 1.1.1.1,2.2.2.2]
// output: one "host=ip1,ip2" line per resolved host (nothing for failures)
import dgram from "node:dgram";
import crypto from "node:crypto";

const argv = process.argv.slice(2);
const hosts = [];
let nsList = ["192.168.1.1", "114.114.114.114", "223.5.5.5"];
// Only IPv4 nameservers are usable here: this resolver speaks udp4, and
// dumpsys connectivity on this phone lists a link-local IPv6 DNS first
// (fddb:51f:2d8a::1) which would just burn a 2.5s timeout on every lookup.
const isV4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--ns") {
    nsList = String(argv[++i] || "").split(",").map(s => s.trim()).filter(Boolean).filter(isV4);
    continue;
  }
  if (argv[i].startsWith("--")) continue;
  hosts.push(argv[i]);
}
nsList = nsList.filter(isV4);
if (!nsList.length) nsList = ["223.5.5.5", "114.114.114.114"];

function buildQuery(host) {
  const labels = host.split(".").filter(Boolean);
  const id = crypto.randomInt(0, 0xffff);
  const parts = [];
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2);
  head.writeUInt16BE(1, 4);
  parts.push(head);
  for (const l of labels) {
    const b = Buffer.from(l, "ascii");
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  const q = Buffer.alloc(4);
  q.writeUInt16BE(1, 0);
  q.writeUInt16BE(1, 2);
  parts.push(q);
  return { id, packet: Buffer.concat(parts) };
}

function parseAnswers(buf, wantId) {
  if (buf.length < 12 || buf.readUInt16BE(0) !== wantId) return null;
  if ((buf.readUInt16BE(2) & 0x000f) !== 0) return null;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
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

function udpQuery(ns, host, timeoutMs = 2500) {
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
    sock.on("message", (msg) => fin(parseAnswers(msg, q.id) || []));
    const q = buildQuery(host);
    try { sock.send(q.packet, 53, ns); } catch { fin([]); }
  });
}

for (const h of hosts) {
  let ips = [];
  for (const ns of nsList) {
    ips = await udpQuery(ns, h);
    if (ips.length) break;
  }
  if (ips.length) process.stdout.write(`${h}=${[...new Set(ips)].join(",")}\n`);
}
process.exit(0);
