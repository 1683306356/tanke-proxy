// patch-runpath2.mjs — rewrite ONLY the DT_RUNPATH string of an ELF64 binary.
//
// The first attempt replaced every occurrence of the Termux lib path in the file.
// That was wrong: node also embeds that path inside a JSON blob in .rodata
// (its build/link config, e.g. "-L/data/data/com.termux/files/usr/lib"), and
// node JSON.parses that blob at startup ->
//   SyntaxError: Bad control character in string literal in JSON at position 22836
//
// So this version parses the ELF properly:
//   section headers -> SHT_DYNAMIC -> sh_link -> .dynstr -> DT_RUNPATH -> offset
// and rewrites exactly the one C string that entry points at. The replacement is
// shorter or equal, so the rest of .dynstr (and the file size) is untouched; the
// leftover bytes become NUL padding of a string nobody can reach.
//
//   node patch-runpath2.mjs <file-or-dir> [...] --from OLD --to NEW
//   node patch-runpath2.mjs <file-or-dir> [...]                (defaults below)

import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
let FROM = "/data/data/com.termux/files/usr/lib";
let TO = "/data/adb/modules/tanke_proxy/lib";
const paths = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--from") FROM = argv[++i];
  else if (argv[i] === "--to") TO = argv[++i];
  else paths.push(argv[i]);
}

const DT_NULL = 0, DT_RPATH = 15, DT_RUNPATH = 29, SHT_DYNAMIC = 6;

function u64(b, o) { return b.readBigUInt64LE(o); }
function u32(b, o) { return b.readUInt32LE(o); }
function u16(b, o) { return b.readUInt16LE(o); }

function elfInfo(buf) {
  if (buf.readUInt32BE(0) !== 0x7f454c46) throw new Error("not ELF");
  if (buf[4] !== 2 || buf[5] !== 1) throw new Error("only ELF64 little-endian supported");
  return {
    shoff: Number(u64(buf, 0x28)),
    shentsize: u16(buf, 0x3a),
    shnum: u16(buf, 0x3c),
  };
}

function section(buf, e, i) {
  const o = e.shoff + i * e.shentsize;
  return {
    name: u32(buf, o),
    type: u32(buf, o + 4),
    offset: Number(u64(buf, o + 24)),
    size: Number(u64(buf, o + 32)),
    link: u32(buf, o + 40),
    entsize: Number(u64(buf, o + 56)),
  };
}

function words(buf) {
  for (let i = 0; i + 4 <= buf.length; i++) {
    if (buf[i] === 0x0a && buf[i + 1] === 0x20) return buf.toString("utf8", i + 2).trim();
  }
  return "";
}

// Returns every location where the file's dynamic section declares a
// RPATH/RUNPATH, as an absolute file offset into the NUL-terminated string.
function runpathOffsets(buf) {
  const e = elfInfo(buf);
  const out = [];
  for (let i = 0; i < e.shnum; i++) {
    const s = section(buf, e, i);
    if (s.type !== SHT_DYNAMIC) continue;
    const strtab = section(buf, e, s.link);
    const entsize = s.entsize || 16;
    for (let o = s.offset; o + entsize <= s.offset + s.size; o += entsize) {
      const tag = Number(buf.readBigInt64LE(o));
      if (tag === DT_NULL) break;
      if (tag !== DT_RPATH && tag !== DT_RUNPATH) continue;
      const val = Number(buf.readBigUInt64LE(o + 8));
      out.push({ tag, strOffset: val, fileOffset: strtab.offset + val });
    }
  }
  return out;
}

function cstrAt(buf, off) {
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.subarray(off, end).toString("latin1");
}

function patch(file) {
  const buf = fs.readFileSync(file);
  let locs;
  try { locs = runpathOffsets(buf); }
  catch (e) { return { file, skip: e.message }; }
  if (!locs.length) return { file, skip: "no DT_RPATH/DT_RUNPATH" };

  let changed = 0;
  const detail = [];
  for (const l of locs) {
    const cur = cstrAt(buf, l.fileOffset);
    detail.push(`${l.tag === DT_RUNPATH ? "RUNPATH" : "RPATH"}=${cur}`);
    if (!cur.includes(FROM)) continue;
    if (cur.startsWith(TO)) continue;
    // rewrite the FIRST component only; a RUNPATH is one C string, so a
    // ':'-separated duplicate past our NUL is simply unreachable
    const first = cur.split(":")[0];
    if (!first.includes(FROM)) continue;
    const repl = first.replace(FROM, TO);
    if (repl.length > first.length) throw new Error(`${file}: replacement longer than original`);
    buf.write(repl, l.fileOffset, "latin1");
    buf.fill(0, l.fileOffset + repl.length, l.fileOffset + first.length);
    changed++;
  }
  if (!changed) return { file, skip: `already clean (${detail.join(" ")})` };
  const size = buf.length;
  fs.writeFileSync(file, buf);
  if (fs.statSync(file).size !== size) throw new Error(`${file}: size changed`);
  return { file, changed, detail: detail.join(" ") };
}

const targets = [];
for (const p of paths) {
  const st = fs.statSync(p);
  if (st.isDirectory()) {
    for (const n of fs.readdirSync(p)) {
      const f = path.join(p, n);
      if (fs.statSync(f).isFile()) targets.push(f);
    }
  } else targets.push(p);
}

let total = 0;
for (const f of targets) {
  const r = patch(f);
  if (r.skip) { console.log(`keep     ${path.basename(f)}  (${r.skip})`); continue; }
  total += r.changed;
  console.log(`patched  ${path.basename(f)}  ${r.detail}  -> ${r.changed} entry`);
}
console.log(`total: ${targets.length} files, ${total} RUNPATH string(s) rewritten`);
