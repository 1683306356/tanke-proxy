#!/usr/bin/env node
// ============================================================================
// adapt-probe.mjs  —  版本适配自检器 / version-adapter self-check
//
// 回答一个具体问题：**当前这份 App 的 sign 规则，和已适配的 4.2.0 是不是一套？**
//
// 用法：
//   node adapt-probe.mjs [日志文件或目录 ...] [--out 报告路径] [--json] [-v]
//   node adapt-probe.mjs                     # 默认读 ./capture.jsonl
//   node adapt-probe.mjs /data/adb/tanke-proxy/capture.jsonl
//   node adapt-probe.mjs --json > r.json     # 机器可读
//
// 输入要求：代理日志（capture.jsonl，proxy.mjs 产出）。**只需要 REQ 记录**——
// proxy.mjs 在改写之前就把客户端原始 body 写进 REQ.bodyText（≤8000 字符，
// body < 20000 字节），所以探测器拿到的永远是「客户端自己算 sign 时用的那份数据」，
// 而不是代理改写后的版本。这一点是整个探测器的地基（见 VERSION_COMPAT.md §0）。
//
// 原理（不依赖代理的任何判断，全部独立重算）：
//   1. 逐条抽 REQ：path + 客户端原始 body
//   2. 拿到**客户端自己算的 sign**
//        - 明文表单体：直接解析 sign=（值先 form-decode）
//        - 加密体 key=<AES>：先用候选 key/iv 解出 JSON，再取 .sign
//   3. 用候选规则矩阵逐个重算，看哪条能**逐字符命中**客户端的 sign
//   4. 与 4.2.0 基线逐请求比对，出结论
//
// 规则标签格式：  <盐>/<排序>/<排除集>/<编码>
//   盐     S = 尾盐 rDJiNB9j7vD2     P = 首盐 eFoqdHOdDy6ViJ0i     N = 无盐
//   排序   K = 键名 ASCII 升序       I = 出现顺序（JSON 键序 / 表单顺序）
//   排除集 字母表，恒排除 sign；只列「本请求里真的有这个字段」的开关：
//            f=file  m=mobileDeviceId  n=nick_name+avatar_url  t=timestamp
//            c=nonce k=token           u=uid                s=student_num
//            h=school_id                v=version+version_name
//          例：`-` = 只排除 sign   `m` = {sign,mobileDeviceId}
//              `fm` = {sign,file,mobileDeviceId}   `fmn` = 再加 nick_name/avatar_url
//   编码   D = 拼串前 form-decode（客户端真实行为）   R = 原样（wire 上的编码）
//
// 关键设计：**期望和实测用同一套归一化**。4.2.0 的排除集里恒有 `file`，
// 但绝大多数请求里根本没有 file 字段 —— 那时「排除 file」和「不排除」算出来一模一样。
// 所以标签只记「本请求里确实存在的开关」，期望值也按同一规则投影，
// 否则会把一个正确的规则误报成 DIFF。
//
// 4.2.0 基线：普通端点 尾盐 S / 键名升序 K / 排除{sign,file} / form-decode
//             w7 端点  首盐 P / K / 排除{sign,file,mobileDeviceId}
//             v7 端点  首盐 P / K / 排除{sign,file,mobileDeviceId,nick_name,avatar_url}
//
// 零依赖：只用 node 内置 fs / crypto / path。
// 退出码：0 = 与 4.2.0 一致   2 = 不一致/部分不一致   3 = 数据不足无法判定
// ============================================================================
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const PROBE_VERSION = "1.0";

// ---------------------------------------------------------------- 4.2.0 基线
// 这些值全部来自 4.2.0 实测（见 VERSION_COMPAT.md）。改 App 版本后可能全变。
const SALT_SUFFIX = "rDJiNB9j7vD2";     // 尾盐，普通端点
const SALT_PREFIX = "eFoqdHOdDy6ViJ0i"; // 首盐，w7 端点

// w7：首盐 + 排除 mobileDeviceId
const BASE_W7 = [
  "Login/quickLoginV339", "Login/RefreshToken", "Run2/beforeRunV260", "Run/stopRunV278",
  "Run2/gyroscope", "Run/setRunLocationRecord", "Report/getOssSign", "report/getOssSts",
];
// v7：在 w7 基础上再排除 nick_name / avatar_url
const BASE_V7 = ["Login/quickLoginV339"];

// 候选 AES key/iv。第一组是「请求加密体」用的，第二组是 system/update 响应用的，
// 后两组是逆向时挖到的备选。探测器对每个加密体都试一遍，命中哪组就报哪组——
// 这样「AES key/iv 变了」能被单独定位出来，不会和 sign 规则变化混在一起。
const AES_CANDS = [
  { k: "goMEzJ1pDpncNHb9", iv: "ZUrAS2lUidjyY2gK", tag: "body@4.2.0" },
  { k: "Wet2C8d34f62ndi3", iv: "K6iv85jBD8jgf32D", tag: "rsp@4.2.0" },
  { k: "HX7jeq!@kA8X4c$5", iv: "2cNe10vz5P9V6Tm$", tag: "alt-A" },
  { k: "J98huiy7EWF78S4a", iv: "p02J7G53rfsJy7yH", tag: "alt-B" },
];

// 排除集开关。sign 永远排除（它是输出）。其余都是「可能被某个版本加进去」的候选。
const SKIP_TOGGLES = [
  { bit: "f", keys: ["file"] },
  { bit: "m", keys: ["mobileDeviceId"] },
  { bit: "n", keys: ["nick_name", "avatar_url"] },
  { bit: "t", keys: ["timestamp"] },
  { bit: "c", keys: ["nonce"] },
  { bit: "k", keys: ["token"] },
  { bit: "u", keys: ["uid"] },
  { bit: "s", keys: ["student_num"] },
  { bit: "h", keys: ["school_id"] },
  { bit: "v", keys: ["version", "version_name"] },
];

// ---------------------------------------------------------------- 小工具
const md5 = (s) => crypto.createHash("md5").update(s, "utf8").digest("hex");

// 客户端拼串用的是「值本身」，wire 上的是 URL 编码后的。
// java.net.URLEncoder 会把字面量 + 编成 %2B，所以 body 里裸 + 只可能是空格。
function formDecode(s) {
  const t = String(s);
  if (t.indexOf("%") < 0 && t.indexOf("+") < 0) return t;
  try { return decodeURIComponent(t.replace(/\+/g, " ")); } catch { return t; }
}

function aesDecrypt(text, k, iv) {
  const b64 = decodeURIComponent(String(text)).replace(/\s+/g, "");
  const d = crypto.createDecipheriv("aes-128-cbc", Buffer.from(k, "utf8"), Buffer.from(iv, "utf8"));
  return Buffer.concat([d.update(Buffer.from(b64, "base64")), d.final()]).toString("utf8");
}

const isHex32 = (s) => typeof s === "string" && /^[0-9a-f]{32}$/i.test(s);

function expandSkipLabel(label) {
  const names = ["sign"];
  for (const t of SKIP_TOGGLES) if (label.includes(t.bit)) names.push(...t.keys);
  return "{" + names.join(",") + "}";
}

function ruleLabel(salt, order, skipLabel, enc) {
  return `${salt}/${order}/${skipLabel || "-"}/${enc}`;
}

function explainRule(label) {
  const parts = String(label).split("/");
  const salt = parts[0], order = parts[1], skip = parts[2], enc = parts[3];
  const saltTxt = salt === "S" ? `尾盐 ${SALT_SUFFIX}`
    : salt === "P" ? `首盐 ${SALT_PREFIX}`
      : salt === "N" ? "无盐" : salt;
  const orderTxt = order === "K" ? "键名升序" : order === "I" ? "出现顺序" : order;
  const encTxt = enc === "D" ? "form-decode" : enc === "R" ? "原样(未解码)" : enc;
  return `${saltTxt} + ${orderTxt} + 排除${expandSkipLabel(skip === "-" ? "" : skip)} + ${encTxt}`;
}

// 同一条请求上经常有多条候选算出同一个 md5（body 里没有需要解码的字符 → D≡R；
// 字段本来就按名排好 → K≡I）。这只是该请求「提供不了区分信息」，不是错误。
// 展示时挑一条最像 4.2.0 习惯的当主标签，其余算别名。
function canonicalOf(labels, expLabel) {
  if (!labels.length) return null;
  const wantSalt = String(expLabel || "").split("/")[0];
  const score = (l) => {
    const p = l.split("/");
    let d = 0;
    if (p[3] !== "D") d += 1;
    if (p[1] !== "K") d += 2;
    if (p[0] !== wantSalt) d += 100;
    return d;
  };
  return labels.slice().sort((a, b) => score(a) - score(b))[0];
}

// 本请求里「真的存在」的开关集合。只有存在的开关才可能改变 hash，
// 也才应该出现在标签里 —— 这是期望/实测可比的前提。
function effectiveToggles(fields) {
  const out = [];
  for (const t of SKIP_TOGGLES) {
    if (t.keys.some((k) => Object.prototype.hasOwnProperty.call(fields, k))) out.push(t);
  }
  return out;
}

// 4.2.0 对该路径的期望，按本请求的 effective 开关投影
function expectedRuleFor(p, effToggles) {
  let want;
  if (BASE_V7.some((s) => p.includes(s))) want = ["f", "m", "n"];
  else if (BASE_W7.some((s) => p.includes(s))) want = ["f", "m"];
  else want = ["f"];
  const salt = want.includes("m") ? "P" : "S";
  const present = new Set(effToggles.map((t) => t.bit));
  const skip = want.filter((b) => present.has(b)).join("");
  return ruleLabel(salt, "K", skip, "D");
}

// ---------------------------------------------------------------- 规则矩阵
// fields: 已解码键值；orderedKeys: 出现顺序；encBody: 是否加密体（加密体没有「编码」维度）
// 返回命中的规则标签数组
function matchRules(fields, orderedKeys, encBody) {
  const labels = [];
  const eff = effectiveToggles(fields);
  const salts = [
    ["S", (body) => body + SALT_SUFFIX],
    ["P", (body) => SALT_PREFIX + body],
    ["N", (body) => body],
  ];
  const encs = encBody ? ["D"] : ["D", "R"];
  const want = fields.__sign;

  for (const [saltName, wrap] of salts) {
    for (const order of ["K", "I"]) {
      const keys = order === "K" ? [...orderedKeys].sort() : orderedKeys;
      for (const enc of encs) {
        // 每种掩码：省略哪个开关
        for (let mask = 0; mask < (1 << eff.length); mask++) {
          const skipKeys = new Set(["sign"]);
          let label = "";
          for (let i = 0; i < eff.length; i++) {
            if (mask & (1 << i)) { label += eff[i].bit; for (const k of eff[i].keys) skipKeys.add(k); }
          }
          const useKeys = keys.filter((k) => !skipKeys.has(k));
          let body = "";
          for (const k of useKeys) {
            const v = enc === "R" && fields.__raw ? fields.__raw[k] : fields[k];
            body += k + String(v);
          }
          if (md5(wrap(body)) === want) labels.push(ruleLabel(saltName, order, label, enc));
        }
      }
    }
  }
  return labels;
}

// ---------------------------------------------------------------- 输入读取
function expandInputs(args) {
  const out = [];
  for (const a of args) {
    let st;
    try { st = fs.statSync(a); } catch { continue; }
    if (st.isDirectory()) {
      for (const f of fs.readdirSync(a)) {
        if (/^capture.*\.jsonl(\.\d+)?$/i.test(f)) out.push(path.join(a, f));
      }
    } else out.push(a);
  }
  if (!out.length && fs.existsSync("capture.jsonl")) out.push("capture.jsonl");
  // 稳定顺序：主日志在前，轮转备份在后
  out.sort();
  return out;
}

function readRecords(files) {
  const recs = [];
  const bad = { lines: 0, parse: 0, dup: 0 };
  const seen = new Set();
  for (const f of files) {
    let txt;
    try { txt = fs.readFileSync(f, "utf8"); } catch { continue; }
    for (const line of txt.split("\n")) {
      if (!line) continue;
      bad.lines++;
      let o;
      try { o = JSON.parse(line); } catch { bad.parse++; continue; }
      // 主日志 + 轮转备份一起读时可能重复（copytruncate 的边缘情况），
      // 按 kind+ts+path 去重，避免把同一条请求数成两条、虚高匹配率。
      const key = `${o.kind}|${o.ts}|${o.path || ""}`;
      if (seen.has(key)) { bad.dup++; continue; }
      seen.add(key);
      o.__file = f;
      recs.push(o);
    }
  }
  return { recs, bad };
}

// 从 REQ 记录里抽出「客户端那一份」请求
function extractRequest(r) {
  const p = String(r.path || "");
  const body = typeof r.bodyText === "string" ? r.bodyText : "";
  // bodyText 被截断（body >= 20000 字节）时的兜底：新 proxy.mjs 会额外记 signTail
  const tail = typeof r.signTail === "string" ? r.signTail : "";
  const src = body || tail;
  if (!src) return { path: p, kind: "no-body" };

  if (/^key=/.test(src)) {
    for (const c of AES_CANDS) {
      let obj;
      try { obj = JSON.parse(aesDecrypt(src.slice(4), c.k, c.iv)); } catch { continue; }
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) continue;
      const orderedKeys = Object.keys(obj).filter((k) => k !== "sign");
      const fields = { __sign: obj.sign, __raw: null };
      for (const k of orderedKeys) fields[k] = obj[k];
      return { path: p, kind: "enc", fields, orderedKeys, aes: c.tag, truncated: !body };
    }
    return { path: p, kind: "enc-undecryptable" };
  }

  if (src.indexOf("=") < 0) return { path: p, kind: "no-body" };
  const pairs = src.split("&").filter(Boolean).map((s) => {
    const i = s.indexOf("=");
    return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)];
  });
  if (!pairs.length) return { path: p, kind: "no-body" };
  const fields = { __sign: null, __raw: {} };
  const orderedKeys = [];
  for (const [rk, rv] of pairs) {
    const k = formDecode(rk);
    fields[k] = formDecode(rv);
    fields.__raw[k] = rv;
    if (!orderedKeys.includes(k)) orderedKeys.push(k);
  }
  fields.__sign = fields.sign;
  return { path: p, kind: "form", fields, orderedKeys: orderedKeys.filter((k) => k !== "sign"), truncated: !body };
}

// ---------------------------------------------------------------- 主流程
function main() {
  const argv = process.argv.slice(2);
  let json = false, verbose = false, outPath = null;
  const inputs = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") json = true;
    else if (a === "-v" || a === "--verbose") verbose = true;
    else if (a === "--out") outPath = argv[++i];
    else if (a === "-h" || a === "--help") { showHelp(); return 0; }
    else inputs.push(a);
  }
  const files = expandInputs(inputs);
  if (!files.length) {
    console.error("adapt-probe: 没有找到日志文件。用法: node adapt-probe.mjs <capture.jsonl 或目录>");
    return 3;
  }
  const { recs, bad } = readRecords(files);
  const reqs = recs.filter((r) => r.kind === "REQ");
  const rewrites = recs.filter((r) => r.kind === "REWRITE");

  const lines = [];
  const say = (s = "") => lines.push(s);
  const stamp = new Date().toISOString().replace("T", " ").replace(/\..+/, "");

  say(`=== adapt-probe v${PROBE_VERSION}  ${stamp} ===`);
  say(`日志: ${files.join(", ")}`);
  say(`记录 ${recs.length} 条（REQ ${reqs.length} / REWRITE ${rewrites.length}）`);

  if (!reqs.length) {
    say("");
    say("[无法判定] 日志里没有任何 REQ 记录。");
    say("  可能原因：代理没跑 / 日志被轮转掉了 / 这份日志不是 proxy.mjs 产出的。");
    say("  下一步：让 App 正常用一次（登录 + 进首页 + 进跑步页），再看 capture.jsonl。");
    emit(lines, outPath, json, { verdict: "no-data", reason: "no REQ records", probe_version: PROBE_VERSION, files, ts: stamp });
    return 3;
  }

  // ---- 逐请求：抽字段 → 各自算期望 → 各自匹配
  const perPath = new Map();
  let unsigned = 0, undec = 0, noBody = 0, oddSign = 0;
  let sameReq = 0, diffReq = 0, unknownReq = 0, discReq = 0, ambReq = 0;
  const failSamples = [];
  const versions = new Set();
  const aesTags = new Set();

  for (const r of reqs) {
    const ex = extractRequest(r);
    if (!perPath.has(ex.path)) perPath.set(ex.path, {
      n: 0, same: 0, diff: 0, unknown: 0, kinds: new Set(), aes: new Set(),
      labels: new Map(), expLabels: new Map(), notes: new Set(), firstDiff: null,
    });
    const st = perPath.get(ex.path);
    st.n++;
    st.kinds.add(ex.kind);

    if (ex.kind === "no-body") { noBody++; st.unknown++; st.notes.add("无 body（body>=20000 字节且 proxy 未记 signTail）"); continue; }
    if (ex.kind === "enc-undecryptable") { undec++; st.unknown++; st.notes.add(`AES 解不开（试了 ${AES_CANDS.length} 组 key/iv）`); continue; }
    if (ex.aes) { st.aes.add(ex.aes); aesTags.add(ex.aes); }
    if (ex.truncated) st.notes.add("bodyText 被截断，只能用 signTail 兜底");
    if (ex.fields.version !== undefined || ex.fields.version_name !== undefined) {
      versions.add(`${ex.fields.version ?? "?"}/${ex.fields.version_name ?? "?"}`);
    }

    const sign = ex.fields.__sign;
    if (!sign) { unsigned++; st.unknown++; st.notes.add("该端点请求体里没有 sign 字段"); continue; }
    if (!isHex32(sign)) {
      oddSign++; st.unknown++;
      st.notes.add(`sign 不是 32 位小写 hex（值=${String(sign).slice(0, 20)}…）→ 可能换成了 SHA256/HMAC`);
      continue;
    }

    const eff = effectiveToggles(ex.fields);
    const exp = expectedRuleFor(ex.path, eff);
    st.expLabels.set(exp, (st.expLabels.get(exp) || 0) + 1);

    const got = matchRules(ex.fields, ex.orderedKeys, ex.kind === "enc");
    if (!got.length) {
      diffReq++; st.diff++;
      if (!st.firstDiff) st.firstDiff = { kind: ex.kind, keys: ex.orderedKeys.slice(0, 24), got: [], exp, sign: sign.slice(0, 12) + "…" };
      if (failSamples.length < 8) failSamples.push({ path: ex.path, kind: ex.kind, keys: ex.orderedKeys.slice(0, 24), sign: sign.slice(0, 12) + "…" });
      continue;
    }
    for (const l of got) st.labels.set(l, (st.labels.get(l) || 0) + 1);
    // 判别力统计：一条请求里若有多个候选算出同一个 md5，说明该请求提供不了区分信息
    if (got.length === 1) discReq++; else ambReq++;
    if (got.includes(exp)) { sameReq++; st.same++; }
    else {
      diffReq++; st.diff++;
      if (!st.firstDiff) st.firstDiff = { kind: ex.kind, keys: ex.orderedKeys.slice(0, 24), got, exp, sign: sign.slice(0, 12) + "…" };
    }
  }

  // 修正 unknown 计数（被上面 diff 逻辑挪动的部分）
  for (const [, st] of perPath) {
    st.unknown = st.n - st.same - st.diff;
    if (st.unknown < 0) st.unknown = 0;
  }
  unknownReq = 0;
  for (const [, st] of perPath) unknownReq += st.unknown;

  // ---- 汇总
  const rows = [...perPath].map(([p, st]) => {
    const verdict = st.same && !st.diff ? "SAME" : st.diff && !st.same ? "DIFF" : st.same && st.diff ? "MIXED" : "UNKNOWN";
    return { path: p, st, verdict };
  });
  const rank = { DIFF: 0, MIXED: 1, UNKNOWN: 2, SAME: 3 };
  rows.sort((a, b) => (rank[a.verdict] - rank[b.verdict]) || (b.st.n - a.st.n));

  say("");
  say("App version（客户端请求里自称）: " + ([...versions].join(", ") || "未知"));
  const verified = sameReq + diffReq;
  say(`请求总数 ${reqs.length}，已验证 ${verified}（一致 ${sameReq} / 不一致 ${diffReq}；未验证 ${unknownReq}）`);
  if (noBody || undec || unsigned || oddSign) {
    say(`  未验证明细: 无 body ${noBody} / AES 解不开 ${undec} / 无 sign ${unsigned} / sign 异常 ${oddSign}`);
  }
  if (bad.parse) say(`  日志里有 ${bad.parse} 行不是合法 JSON，已跳过`);
  if (bad.dup) say(`  主日志与轮转备份之间有 ${bad.dup} 条重复记录，已去重`);

  // ---- 逐端点明细表
  say("");
  say("[逐端点规则]");
  say("  " + pad("端点", 50) + pad("n", 5) + pad("判定", 9) + "实测主规则（+别名数）");
  for (const r of rows) {
    const got = [...r.st.labels.keys()];
    const expFirst = [...r.st.expLabels.keys()][0] || "";
    const canon = canonicalOf(got, expFirst);
    const shown = canon ? canon + (got.length > 1 ? `  +${got.length - 1} 个等价别名` : "") : "—";
    const mark = r.verdict === "SAME" ? "一致" : r.verdict === "DIFF" ? "**不同**" : r.verdict === "MIXED" ? "**混合**" : "未判定";
    say("  " + pad(r.path, 50) + pad(String(r.st.n), 5) + pad(mark, 9) + shown);
  }
  say("");
  const anyMatch = discReq + ambReq;
  if (!anyMatch) {
    say("[判别力] 没有任何一条请求能被候选规则命中——不是「body 不够」的问题，是规则本身不对。");
  } else {
    say(`[判别力] ${discReq} 个请求只被唯一一条规则命中，${ambReq} 个请求有多条候选算出同一个 md5`);
    say("  （后者不是问题：body 里没有需要 URL 解码的字符时 D≡R，字段本来就按名排好时 K≡I。");
    say("    真正能区分 D/R 的端点如 Report/appLog（fileName 含 %2F），只有它会给唯一命中。）");
  }

  const badRows = rows.filter((r) => r.verdict === "DIFF" || r.verdict === "MIXED");
  const unkRows = rows.filter((r) => r.verdict === "UNKNOWN");

  // 主规则归纳（只统计「一致」的请求）
  const tally = new Map();
  for (const r of rows) if (r.verdict === "SAME" || r.verdict === "MIXED") {
    for (const [l, c] of r.st.labels) tally.set(l, (tally.get(l) || 0) + c);
  }
  const top = [...tally].sort((a, b) => b[1] - a[1]).slice(0, 4);

  // ---- 结论
  say("");
  say("[结论]");
  if (!badRows.length) {
    say(`  全部 ${rows.length} 个端点、${sameReq} 个请求都命中 4.2.0 的规则`);
    say("  → sign 规则与 4.2.0 完全一致，可以直接用现有模块。");
    if (top.length) say(`  主规则 ${top[0][0]}  (${top[0][1]}/${sameReq})  = ${explainRule(top[0][0])}`);
  } else {
    say(`  ${sameReq}/${verified} 个命中 4.2.0 规则；${badRows.length} 个端点对不上：`);
    for (const r of badRows.slice(0, 12)) {
      const got = [...r.st.labels.keys()];
      say(`    ${r.path}  (${r.st.n} 次, 一致 ${r.st.same} / 不一致 ${r.st.diff})`);
      say(`        期望 ${[...r.st.expLabels.keys()].join(" | ")}  = ${explainRule([...r.st.expLabels.keys()][0])}`);
      say(`        实测 ${got.length ? got.slice(0, 4).join(" | ") : "（无任何候选命中）"}`);
      if (r.st.firstDiff) say(`        样本 kind=${r.st.firstDiff.kind} clientSign=${r.st.firstDiff.sign} keys=[${r.st.firstDiff.keys.join(",")}]`);
    }
    if (badRows.length > 12) say(`    …另有 ${badRows.length - 12} 个端点`);
    if (unkRows.length) say(`  另有 ${unkRows.length} 个端点未能判定（见上表「未判定」与下方说明）。`);
  }

  // ---- AES
  if (aesTags.size) {
    const bodyOk = aesTags.has("body@4.2.0");
    say("");
    say("[AES] 请求加密体解出的 key/iv: " + [...aesTags].join(", ") +
      (bodyOk ? "  → 与 4.2.0 一致" : "  → **不是 4.2.0 的请求 key，AES 已变**"));
  }
  if (undec) {
    say("");
    say(`[AES] ${undec} 个加密体用全部 ${AES_CANDS.length} 组候选 key/iv 都解不开`);
    say("  → 请求加密换了 key/iv 或换了算法，sign 规则无从谈起，先重逆 AES。");
  }

  // ---- 未判定端点的说明
  if (unkRows.length) {
    say("");
    say("[未判定端点]");
    for (const r of unkRows.slice(0, 10)) say(`  ${r.path} (${r.st.n} 次): ${[...r.st.notes].join("；") || "原因不明"}`);
  }

  // ---- 未命中样本
  if (failSamples.length) {
    say("");
    say("[未命中样本] 拿这些照 VERSION_COMPAT.md 的「症状 → 可能原因 → 怎么确认」逐项试");
    for (const s of failSamples) say(`  ${s.path}  kind=${s.kind}  clientSign=${s.sign}  keys=[${s.keys.join(",")}]`);
  }

  // ---- 下一步
  say("");
  say("[下一步]");
  const anyMatchToo = discReq + ambReq;
  // 有命中、但命中的盐全都不是期望的那个 → 诊断成「盐变了」
  const saltMismatch = badRows.length && badRows.every((r) => {
    const got = [...r.st.labels.keys()];
    const exp = [...r.st.expLabels.keys()][0] || "";
    return got.length && got.every((l) => l.split("/")[0] !== exp.split("/")[0]);
  });
  if (!badRows.length) {
    say("  直接装现有模块即可。若上表有「未判定」的端点，让 App 多走一遍对应页面再复测。");
  } else if (!anyMatchToo) {
    say("  全局规则对不上：所有请求用「有盐/无盐 × 两种排序 × 两种编码 × 任意排除集」都算不出来。");
    say("  只可能是这三者之一（按可能性排序）：① 盐值变了 ② 拼串方式变了（如中间加分隔符）");
    say("  ③ 哈希从 md5 换成别的。先抓一条真实请求的明文体，手工算 md5 输入，逐项排除。");
    say("  盐在 4.2.0 里是常量：找算 sign 的函数（Lg/a0/c/e0/j3/k;->e），读回来填进 proxy.mjs。");
  } else if (saltMismatch) {
    say("  盐变了（首/尾盐与 4.2.0 不同），或首尾盐的角色对调了 → 全站 sign 都会挂，服务端只回「非法请求」。");
    say("  需要重新逆盐：找算 sign 的函数（4.2.0 在 Lg/a0/c/e0/j3/k;->e），读两个常量，填回 proxy.mjs。");
  } else if (badRows.some((r) => [...r.st.labels.keys()].length === 0)) {
    say("  部分端点连任意排除集都算不出来 → 这些端点的拼串方式或哈希算法单独变了。");
    say("  用 decrypt 拿一条该端点的明文，手工比对 md5 输入，再决定改哪一层。");
  } else {
    say("  排除集或编码变了（盐对得上）。把上表「实测」与「期望」的差异字母改成 proxy.mjs 的 W7/V7 名单即可。");
    say("  字母表：f=file m=mobileDeviceId n=nick_name+avatar_url t=timestamp c=nonce k=token");
    say("          u=uid s=student_num h=school_id v=version+version_name");
  }

  if (verbose) {
    say("");
    say("[明细] 每端点命中的全部候选规则");
    for (const r of rows) {
      say(`  ${r.path}  (${r.st.n} 次, kind=${[...r.st.kinds].join("/")})`);
      for (const [l, c] of r.st.labels) say(`      ${pad(l, 12)} x${pad(String(c), 4)} = ${explainRule(l)}`);
      if (r.st.diff) say(`      (${r.st.diff} 次无任何候选命中)`);
      for (const n of r.st.notes) say(`      note: ${n}`);
    }
  }

  const verdict = badRows.length ? "inconsistent" : "consistent";
  const code = badRows.length ? 2 : 0;
  emit(lines, outPath, json, {
    verdict, probe_version: PROBE_VERSION, ts: stamp, files,
    total_requests: reqs.length, verified, same: sameReq, diff: diffReq, unknown: unknownReq,
    versions: [...versions], aes: [...aesTags],
    main_rule: top.length ? { label: top[0][0], count: top[0][1], explain: explainRule(top[0][0]) } : null,
    endpoints: rows.map((r) => ({
      path: r.path, n: r.st.n, verdict: r.verdict,
      same: r.st.same, diff: r.st.diff, unknown: r.st.unknown,
      expected: [...r.st.expLabels.keys()], matched: [...r.st.labels.keys()],
      notes: [...r.st.notes],
    })),
  });
  return code;
}

function pad(s, n) {
  s = String(s);
  // 中文按 2 个显示宽度算，简单的等宽对齐
  let w = 0;
  for (const ch of s) w += ch.charCodeAt(0) > 0x2e80 ? 2 : 1;
  return s + " ".repeat(Math.max(0, n - w));
}

function showHelp() {
  console.log(`adapt-probe v${PROBE_VERSION} — 检查当前 App 的 sign 规则是否与 4.2.0 一致

用法: node adapt-probe.mjs [日志/目录 ...] [--out 路径] [--json] [-v]

  (无参数)            读当前目录的 capture.jsonl
  --out PATH          报告写到 PATH（默认与日志同目录的 adapt-probe-report.txt）
  --json              输出机器可读 JSON
  -v, --verbose       打印每端点命中的全部候选规则

退出码: 0=与 4.2.0 一致  2=不一致  3=数据不足`);
}

// 输出：控制台 + 报告文件（--out / $ADAPT_OUT / 日志同目录）
function emit(lines, outPath, json, obj) {
  const text = lines.join("\n");
  if (json) {
    process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
  } else {
    process.stdout.write(text + "\n");
  }
  let target = outPath || process.env.ADAPT_OUT || null;
  if (!target) {
    const first = (obj && obj.files && obj.files[0]) || "capture.jsonl";
    const dir = path.dirname(first) || ".";
    target = path.join(dir, "adapt-probe-report.txt");
  }
  try {
    fs.writeFileSync(target, text + "\n");
    if (!json) process.stdout.write(`\n[报告已写入] ${target}\n`);
  } catch (e) {
    process.stderr.write(`[warn] 报告写盘失败: ${e.message}\n`);
  }
}

process.exitCode = main();
