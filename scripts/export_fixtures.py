"""Export sanitized fixtures from the local collector database and snapshots.

Usage (from the repo root):
    python scripts/export_fixtures.py --account-id 693333082201 --extra ali

Reads  : data/local/events.db  and  data/local/snapshots/*.json
Writes : fixtures/sanitized/<table>.jsonl  and  fixtures/sanitized/config_snapshots/*.json

What it replaces (the same real value always gets the same fake value):
  * the AWS account ID you pass in, and any 12-digit ID inside an ARN
  * access key IDs (AKIA... / ASIA...)
  * IAM principal IDs (AIDA... / AROA... etc.)
  * AWS resource IDs: eni- i- sg- vpc- subnet- ami- igw- rtb-
  * public IPv4 addresses -> 203.0.113.x (documentation range)
  * IAM user, MFA device and role-session names inside ARNs
  * "userName" fields (same fake name as in the ARN)
  * "userAgent" fields -> "lab-client" (browser/OS strings identify your machine)
  * every --extra word (case-insensitive) anywhere, e.g. your real name
Private 10.x / 172.16-31.x / 192.168.x addresses are KEPT, because detection
needs the 10.20.1.10 -> 10.20.2.10 relationship. Change KEEP_PRIVATE_IPS to
False to replace them too.

It re-scans its own output and exits with an error if anything sensitive is left.
Always read the output files before you commit them.
"""
import argparse
import ipaddress
import json
import re
import sqlite3
import sys
from pathlib import Path

KEEP_PRIVATE_IPS = True

# Pools for fake public IPs: the three documentation ranges first (254 hosts each),
# then the 198.18.0.0/15 benchmarking range (about 131k hosts) for logs with many scanners.
FAKE_IP_NETS = [ipaddress.ip_network(n) for n in (
    "203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24", "198.18.0.0/15")]

RESOURCE_RE = re.compile(r"\b(eni|i|sg|vpc|subnet|ami|igw|rtb)-[0-9a-f]{8,17}\b")
ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
PRINCIPAL_RE = re.compile(r"\b(AIDA|AROA|AIPA|ANPA|AGPA)[A-Z0-9]{12,}\b")
# not preceded by a digit/dot, nor by "Letters/" (so Chrome/138.0.0.0 is not an IP)
IPV4_RE = re.compile(r"(?<![\d.])(?<![A-Za-z]/)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
ARN_ACCOUNT_RE = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(:)")
ARN_USER_RE = re.compile(r"(:(?:user|mfa)/)([A-Za-z0-9+=,.@_/-]+?)(?=$|[\s\",\]}\\])")
ARN_SESSION_RE = re.compile(r"(assumed-role/[A-Za-z0-9+=,.@_-]+/)([A-Za-z0-9+=,.@_-]+)")
# JSON fields, tolerant of the backslash-escaped quotes found inside the "raw" column
USERNAME_RE = re.compile(r'(\\*"userName\\*"\s*:\s*\\*")([^"\\]+)')
USERAGENT_RE = re.compile(r'(\\*"userAgent\\*"\s*:\s*\\*")([^"\\]*)')


def word_re(word):
    """Whole-word, case-insensitive match, so 'ali' does not hit 'Virtualization'."""
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])", re.IGNORECASE)


class Sanitizer:
    def __init__(self, account_id, extras=()):
        self.account_id = account_id
        self.extras = [e for e in extras if e]
        self.maps = {}

    def _fake(self, kind, real, template):
        table = self.maps.setdefault(kind, {})
        if real not in table:
            table[real] = template.format(n=len(table) + 1)
        return table[real]

    def _fake_public_ip(self, real):
        table = self.maps.setdefault("ip", {})
        if real not in table:
            n = len(table)
            for net in FAKE_IP_NETS:
                size = net.num_addresses - 2
                if n < size:
                    table[real] = str(net.network_address + 1 + n)
                    break
                n -= size
            else:
                raise RuntimeError("too many distinct public IPs to anonymize")
        return table[real]

    def _ip(self, m):
        text = m.group(0)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        if ip.is_private and KEEP_PRIVATE_IPS:
            return text
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return text
        return self._fake_public_ip(text)

    def clean(self, text):
        if self.account_id:
            text = text.replace(self.account_id, "111122223333")
        text = ARN_ACCOUNT_RE.sub(r"\g<1>111122223333\g<3>", text)
        text = ACCESS_KEY_RE.sub(lambda m: self._fake("key", m.group(0), "AKIAEXAMPLEKEY{n:06d}"), text)
        text = PRINCIPAL_RE.sub(
            lambda m: self._fake("principal", m.group(0), "AIDAEXAMPLEPRINC{n:04d}"), text)
        text = RESOURCE_RE.sub(
            lambda m: self._fake(m.group(1), m.group(0), m.group(1) + "-" + "{n:017d}"), text)
        text = ARN_USER_RE.sub(lambda m: m.group(1) + self._fake("user", m.group(2), "lab-user-{n}"), text)
        text = ARN_SESSION_RE.sub(lambda m: m.group(1) + self._fake("sess", m.group(2), "session-{n}"), text)
        text = USERNAME_RE.sub(lambda m: m.group(1) + self._fake("user", m.group(2), "lab-user-{n}"), text)
        text = USERAGENT_RE.sub(lambda m: m.group(1) + "lab-client", text)
        text = IPV4_RE.sub(self._ip, text)
        for word in self.extras:
            text = word_re(word).sub("redacted", text)
        return text


def leftovers(text, account_id, extras=()):
    found = []
    if account_id and account_id in text:
        found.append("real account id")
    if ACCESS_KEY_RE.search(text) and "AKIAEXAMPLEKEY" not in text:
        found.append("access key id")
    for m in PRINCIPAL_RE.finditer(text):
        if not m.group(0).startswith("AIDAEXAMPLEPRINC"):
            found.append("principal id " + m.group(0))
    for m in USERNAME_RE.finditer(text):
        if not m.group(2).startswith("lab-user-"):
            found.append("userName " + m.group(2))
    for m in USERAGENT_RE.finditer(text):
        if m.group(2) != "lab-client":
            found.append("userAgent " + m.group(2)[:40])
    for word in extras:
        if word and word_re(word).search(text):
            found.append("extra word " + word)
    for m in IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_global and not m.group(0).startswith("203.0.113."):
            found.append("public ip " + m.group(0))
    for m in RESOURCE_RE.finditer(text):
        if not re.fullmatch(r"[a-z]+-0{0,16}\d{1,6}", m.group(0)) and "-0000000000" not in m.group(0):
            found.append("resource id " + m.group(0))
    return found


def export_tables(db_path, out_dir, san, limit):
    written = []
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
    for table in tables:
        path = out_dir / (table + ".jsonl")
        sql = f'select * from "{table}"' + (f" limit {int(limit)}" if limit else "")
        count = 0
        with path.open("w", encoding="utf-8") as fh:
            for row in con.execute(sql):
                rec = {}
                for key in row.keys():
                    val = row[key]
                    rec[key] = san.clean(val) if isinstance(val, str) else val
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                count += 1
        written.append((path, count))
    con.close()
    return written


def export_snapshots(snap_dir, out_dir, san):
    written = []
    if not snap_dir.exists():
        return written
    target = out_dir / "config_snapshots"
    target.mkdir(parents=True, exist_ok=True)
    for src in sorted(snap_dir.glob("*.json")):
        text = san.clean(src.read_text(encoding="utf-8"))
        json.loads(text)  # must still be valid JSON
        dest = target / src.name
        dest.write_text(text, encoding="utf-8")
        written.append((dest, 1))
    return written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/local/events.db")
    ap.add_argument("--snapshots", default="data/local/snapshots")
    ap.add_argument("--out", default="fixtures/sanitized")
    ap.add_argument("--account-id", default="", help="your real 12-digit AWS account ID")
    ap.add_argument("--extra", action="append", default=[],
                    help="extra word to redact everywhere, e.g. your real name (repeatable)")
    ap.add_argument("--limit", type=int, default=0, help="max rows per table (0 = all)")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    san = Sanitizer(args.account_id, args.extra)

    written = []
    if Path(args.db).exists():
        written += export_tables(args.db, out_dir, san, args.limit)
    else:
        print(f"note: {args.db} not found, skipping database tables")
    written += export_snapshots(Path(args.snapshots), out_dir, san)

    if not written:
        sys.exit("nothing exported: check the --db and --snapshots paths")

    problems = []
    for path, count in written:
        issues = sorted(set(leftovers(path.read_text(encoding="utf-8"), args.account_id, args.extra)))
        print(f"{path}: {count} record(s)" + (f"  LEFTOVERS: {issues}" if issues else ""))
        problems += [(str(path), i) for i in issues]
    if problems:
        sys.exit("sensitive values remain, do NOT commit these files")
    print("check passed: no account id, access key, principal id, userName, userAgent or public IP found. Now READ the files before you commit.")


if __name__ == "__main__":
    main()
