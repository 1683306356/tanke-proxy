#!/usr/bin/env python3
"""Local release scan. Reports locations and categories, never matched values.

Usage: python3 tools/audit-release.py SOURCE_DIRECTORY_OR_ZIP
Exit 0: no rule hits; 1: findings; 2: unreadable/unsupported input.
Pattern matches require review; a clean result is not a guarantee of anonymity.
This scans the selected distribution, including nested ZIP members, not Git history.
"""
import argparse
import io
import json
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

RULES = {
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "provider_token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"
        r"|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}"
        r"|xox[baprs]-[A-Za-z0-9-]{16,})\b"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
    "hex32_review": re.compile(
        r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32}(?![A-Za-z0-9])"
    ),
    "uuid_review": re.compile(
        r"(?<![A-Za-z0-9])[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}"
        r"-[A-Fa-f0-9]{12}(?![A-Za-z0-9])"
    ),
    "student_id_review": re.compile(r"\bW[0-9]{9}\b"),
    "mobile_number_review": re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])"),
    "email_review": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "personal_windows_path_review": re.compile(
        r"(?:[A-Za-z]:[\\/]+|/mnt/[a-z]/)Users[\\/]+[^\s\\/\"'<>]+"
    ),
    "personal_unix_path_review": re.compile(
        r"(?<!/files)/(?:home|Users)/[^\s/\"'<>]+"
    ),
}
PRIVATE_EXTS = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".der", ".crt", ".cer",
    ".apk", ".png", ".jpg", ".jpeg", ".pcap", ".pcapng", ".har", ".tgz", ".tar",
    ".sqlite", ".sqlite3", ".db",
}
PRIVATE_DIRS = {".git", ".svn", ".hg", ".codex", "backup", "dump", "logs", "node_modules"}
# Explicitly approved public author contact. Restrict it to labeled publication lines.
PUBLIC_CONTACTS = {"1683306356" + "@" + "qq.com"}
PUBLIC_CONTACT_FILES = {"LICENSE", "README.md", "PUBLISH.md"}
MAX_ENTRY = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DEPTH = 5


class Scanner:
    def __init__(self):
        self.findings = []
        self.file_count = 0
        self.archive_count = 0
        self.total = 0
        self.approved_public_metadata = []

    def add(self, kind, location, **extra):
        self.findings.append({"type": kind, "path": location, **extra})

    def filename(self, name, location):
        parts = PurePosixPath(name.replace("\\", "/")).parts
        if any(p.lower() in PRIVATE_DIRS for p in parts):
            self.add("private_directory", location)
        leaf = parts[-1].lower() if parts else ""
        if (Path(leaf).suffix in PRIVATE_EXTS or ".jsonl" in leaf
                or leaf.endswith(".log") or ".log." in leaf
                or leaf.startswith("adapt-probe-report")
                or leaf in {"state.env", "health.env", "watchdog.pid", ".heartbeat", ".env"}
                or leaf.startswith(".env.")):
            self.add("private_or_debug_file_review", location)

    def file(self, name, location, data, depth=0):
        self.filename(name, location)
        self.file_count += 1
        self.total += len(data)
        if self.total > MAX_TOTAL:
            raise ValueError("Total scan size exceeded")
        if data[:4] in {b"PK\x03\x04", b"PK\x05\x06"} or name.lower().endswith(".zip"):
            self.archive(location, data, depth + 1)
            return
        texts = [data.decode("utf-8-sig", errors="replace")]
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            texts.append(data.decode("utf-16", errors="replace"))
        seen = set()
        approved_seen = set()
        leaf = PurePosixPath(location.rsplit("!", 1)[-1]).name
        for text in texts:
            text_lines = text.splitlines()
            for kind, pattern in RULES.items():
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    key = (kind, line)
                    line_text = text_lines[line - 1] if text_lines else ""
                    if (kind == "email_review" and match.group() in PUBLIC_CONTACTS
                            and leaf in PUBLIC_CONTACT_FILES
                            and line_text.lstrip().startswith(("授权联系：", "授权联系:"))):
                        if key not in approved_seen:
                            self.approved_public_metadata.append({
                                "type": "approved_author_contact", "path": location, "line": line,
                            })
                            approved_seen.add(key)
                        continue
                    if key not in seen:
                        self.add(kind, location, line=line)
                        seen.add(key)

    def archive(self, location, data, depth):
        if depth > MAX_DEPTH:
            raise ValueError("Nested ZIP depth exceeded")
        self.archive_count += 1
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ValueError("ZIP entry limit exceeded")
            if archive.comment:
                self.add("zip_comment_review", location)
            names = set()
            for entry in entries:
                name = entry.filename.replace("\\", "/")
                child = location + "!" + name
                parts = PurePosixPath(name).parts
                if (name.startswith("/") or re.match(r"^[A-Za-z]:", name)
                        or ".." in parts or "\\" in entry.filename):
                    self.add("unsafe_zip_path", child)
                normalized = name.casefold().rstrip("/")
                if normalized in names:
                    self.add("duplicate_zip_path", child)
                names.add(normalized)
                if entry.comment:
                    self.add("zip_member_comment_review", child)
                if entry.extra:
                    self.add("zip_extra_metadata_review", child)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    self.add("zip_symlink", child)
                    continue
                if entry.flag_bits & 1:
                    self.add("encrypted_zip_entry", child)
                    continue
                if entry.file_size > MAX_ENTRY:
                    raise ValueError("ZIP member size exceeded")
                if entry.is_dir():
                    self.filename(name, child)
                    continue
                self.file(name, child, archive.read(entry), depth)

    def scan(self, target):
        if target.is_symlink():
            self.add("filesystem_symlink", target.name)
        elif target.is_dir():
            for path in sorted(target.rglob("*")):
                rel = path.relative_to(target).as_posix()
                if path.is_symlink():
                    self.add("filesystem_symlink", rel)
                elif path.is_file():
                    if path.stat().st_size > MAX_ENTRY:
                        raise ValueError("File size exceeded")
                    self.file(rel, rel, path.read_bytes())
        elif target.is_file():
            if target.stat().st_size > MAX_ENTRY:
                raise ValueError("File size exceeded")
            self.file(target.name, target.name, target.read_bytes())
        else:
            raise ValueError("Input does not exist")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    scanner = Scanner()
    try:
        scanner.scan(args.target)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        print(json.dumps({"status": "error", "reason": "Input unreadable or archive limit/format failure"}))
        return 2
    print(json.dumps({
        "status": "review" if scanner.findings else "no_rule_hits",
        "files_scanned": scanner.file_count,
        "archives_scanned": scanner.archive_count,
        "findings": scanner.findings,
        "approved_public_metadata": scanner.approved_public_metadata,
        "limitations": "Pattern scan only; manually review identity context, protocol constants and third-party rights. No Git-history scan.",
    }, ensure_ascii=False, indent=2))
    return 1 if scanner.findings else 0


if __name__ == "__main__":
    sys.exit(main())
