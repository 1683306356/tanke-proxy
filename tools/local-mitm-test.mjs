// local-mitm-test.mjs — proves the leaf table actually serves TLS for the 3 hosts.
// Boots the real proxy.mjs on loopback, connects with SNI = each intercept host,
// verifies the presented certificate against the CA only, then checks the proxy's
// own capture log said intercept=true.
import { spawn } from "node:child_process";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const dir = path.resolve(process.argv[2] || ".");
const port = parseInt(process.argv[3] || "18888", 10);
const hosts = ["api2.lptiyu.com", "api.lptiyu.com", "pre-api.lptiyu.com"];
const caPem = fs.readFileSync(path.join(dir, "ca.crt.pem"), "utf8");
const log = path.join(dir, "capture.jsonl");

try { fs.unlinkSync(log); } catch { }

const env = {
  ...process.env,
  PORT: String(port),
  BIND: "127.0.0.1",
  CERT_DIR: dir,
  LEAF_DIR: path.join(dir, "leafs"),
  HEARTBEAT: path.join(dir, ".heartbeat"),
  TARGETS_FILE: path.join(dir, "targets.env"),
};
const p = spawn(process.execPath, [path.join(dir, "proxy.mjs")], { env, cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
let out = "";
p.stdout.on("data", (d) => { out += d.toString(); });
p.stderr.on("data", (d) => { out += d.toString(); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const connect = (host) => new Promise((resolve) => {
  const c = tls.connect({
    port, host: "127.0.0.1", servername: host, ca: caPem, rejectUnauthorized: true,
    checkServerIdentity: (_h, cert) => tls.checkServerIdentity(host, cert),
  }, () => {
    const cert = c.getPeerCertificate();
    resolve({ ok: true, authorized: c.authorized, cn: cert.subject?.CN, san: cert.subjectaltname, proto: c.getProtocol() });
    c.destroy();
  });
  c.on("error", (e) => resolve({ ok: false, err: e.message }));
  c.setTimeout(6000, () => { c.destroy(); resolve({ ok: false, err: "timeout" }); });
});

const results = [];
await sleep(1200);
for (const h of hosts) results.push({ host: h, ...(await connect(h)) });
await sleep(400);
p.kill("SIGTERM");
await sleep(300);

const lines = (fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n") : [])
  .filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return { raw: l }; } });
const tlsRecs = lines.filter((r) => r.kind === "TLS");

let fail = 0;
console.log("--- proxy stdout ---");
console.log(out.trim().split("\n").slice(0, 12).join("\n"));
console.log("--- handshake results ---");
for (const r of results) {
  const rec = tlsRecs.find((t) => t.sni === r.host);
  const ok = r.ok && r.authorized && rec && rec.intercept === true;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${r.host}  authorized=${r.authorized} cn=${r.cn} san=${r.san} proxyLog=${rec ? "intercept=" + rec.intercept : "none"}`);
}
console.log("--- capture kinds ---");
console.log(tlsRecs.map((t) => `${t.kind} ${t.sni} intercept=${t.intercept}`).join("\n") || "(none)");
const leafMiss = lines.filter((r) => r.kind === "LEAF_MISS");
if (leafMiss.length) console.log("LEAF_MISS: " + JSON.stringify(leafMiss));
console.log(fail === 0 ? "RESULT: ALL PASS" : `RESULT: ${fail} FAILURES`);
process.exit(fail === 0 ? 0 : 1);
