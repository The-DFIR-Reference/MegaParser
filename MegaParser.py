"""
MegaParser — MEGAsync Log Extractor
====================================
Processes X-Ways Forensics search hit exports and produces structured CSV
output suitable for Excel workbook assembly and presentation to legal counsel.

Designed for use in incident response investigations where MEGAsync application
logs have been deleted but log content survives in unallocated disk space.
See the accompanying README for the full methodology and XWF configuration.

Usage
-----
  python MegaParser.py --input search_hits.tsv
  python MegaParser.py --inputdir C:\\extracted\\files
  python MegaParser.py --input hits.tsv --outdir C:\\output
  python MegaParser.py --input hits.tsv --encoding utf-16
  python MegaParser.py --list-encodings

Output
------
  confirmed_uploads.csv      Verified exfiltrated files
  access_denied.csv          Files targeted but unreadable
  failed_transfers.csv       Files with general transfer errors
  mega_endpoints.csv         MEGA upload server hostnames
  mega_ips.csv               Resolved destination IP addresses
  investigation_summary.txt  Cover-sheet summary for legal counsel
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from charset_normalizer import from_bytes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "4.0"

OUT_CONFIRMED = "confirmed_uploads.csv"
OUT_DENIED    = "access_denied.csv"
OUT_FAILED    = "failed_transfers.csv"
OUT_ENDPOINTS = "mega_endpoints.csv"
OUT_IPS       = "mega_ips.csv"
OUT_SUMMARY   = "investigation_summary.txt"

DEFAULT_CONFIDENCE_THRESHOLD = 0.7
ENCODING_FALLBACK = "utf-8"


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------
#
# Two patterns run against the per-file joined stream because the records they
# target span multiple XWF context-window rows:
#
#   _PAT_VERIFIED  — "Verifying upload: <path> [transfer.cpp"
#   _PAT_SIZE      — same anchor, extended to capture the FA debug fp size
#
# Windows paths cannot contain '[', so [^\[]+ stops precisely at the first
# bracket, which on a valid record is always [transfer.cpp. This prevents
# overrun into adjacent log entries regardless of stream length.
#
# All other patterns are self-contained within a single ~98-char XWF row and
# run against individual rows using the simple .*? anchor approach.

_PAT_VERIFIED = re.compile(
    r'Verifying upload:\s+([^\[]+?)\s+\[transfer\.cpp',
    re.IGNORECASE,
)
_PAT_SIZE = re.compile(
    r'Verifying upload:\s+([^\[]+?)\s+\[transfer\.cpp.{0,400}?FA debug fp:\s*(\d+):',
    re.IGNORECASE,
)
_PAT_ENDPOINT = re.compile(
    r'\b(gfs\d{2,4}n\d{2,4}\.userstorage\.mega\.co\.nz)\b',
    re.IGNORECASE,
)
_PAT_IP = re.compile(
    r'CURLMSG_DONE.*?mega\.co\.nz\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)
_PAT_DENIED = re.compile(
    r'Access denied File:\s+(.*?)\s+\[megaapi_impl\.cpp',
    re.IGNORECASE,
)
_PAT_FAILED = re.compile(
    r'transfer->name\s*=\s*(.*?)\s*\[megaapi',
    re.IGNORECASE,
)
_PAT_SUBTRANSFER = re.compile(
    r'MegaRecursiveOperation finished subtransfers:\s*(\d+)\s+of\s+(\d+)',
    re.IGNORECASE,
)
_PAT_ERROR  = re.compile(r'finished with error', re.IGNORECASE)
_PAT_DENIED_GUARD = re.compile(r'Access denied', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ParsedResults:
    verified_paths: set[str]             = field(default_factory=set)
    size_map:       dict[str, int]       = field(default_factory=dict)
    endpoints:      set[str]             = field(default_factory=set)
    ips:            set[str]             = field(default_factory=set)
    denied:         set[str]             = field(default_factory=set)
    failed:         set[str]             = field(default_factory=set)
    subtransfers:   set[tuple[int, int]] = field(default_factory=set)


@dataclass
class PathComponents:
    full_path:    str
    filename:     str
    extension:    str
    directory:    str
    source_drive: str


# ---------------------------------------------------------------------------
# Encoding detection
# ---------------------------------------------------------------------------

def detect_encoding(path: Path, confidence_threshold: float, silent: bool = False) -> str:
    """
    Return the encoding for *path*.

    A BOM is an explicit encoding declaration and is checked first — it is
    always definitive and requires no statistical analysis. This reliably
    handles XWF TSV exports (UTF-16 LE with BOM) even when the file contains
    binary slack-space content that defeats statistical detectors.

    charset-normalizer is used as a fallback only for files without a BOM.
    """
    sample = path.read_bytes()[:65_536]

    if sample[:3] == b'\xef\xbb\xbf':
        encoding = 'utf-8-sig'
    elif sample[:2] in (b'\xff\xfe', b'\xfe\xff'):
        encoding = 'utf-16'
    else:
        result = from_bytes(sample).best()
        if result is None or result.chaos > (1.0 - confidence_threshold):
            print(
                f"[WARN] Encoding detection inconclusive for {path.name} "
                f"(confidence below {confidence_threshold:.0%}). "
                f"Defaulting to {ENCODING_FALLBACK}. "
                f"Use --encoding to override."
            )
            return ENCODING_FALLBACK
        encoding = result.encoding

    if not silent:
        print(f"[*] Detected encoding: {encoding} ({path.name})")
    return encoding


# ---------------------------------------------------------------------------
# Input readers
# ---------------------------------------------------------------------------

def _read_lines(path: Path, encoding: str) -> list[str]:
    """Read *path* and return normalised non-blank lines."""
    rows = []
    with open(path, encoding=encoding, errors="replace") as fh:
        for line in fh:
            normalised = line.rstrip("\n\r").replace("\t", " ")
            if normalised.strip():
                rows.append(normalised)
    return rows


def read_file(
    path: Path,
    encoding: Optional[str],
    confidence_threshold: float,
    silent: bool = False,
) -> list[str]:
    """Read a single export file and return its normalised lines."""
    resolved = encoding or detect_encoding(path, confidence_threshold, silent=silent)
    return _read_lines(path, resolved)


def read_directory(
    directory: Path,
    encoding: Optional[str],
    confidence_threshold: float,
) -> list[list[str]]:
    """
    Read every file under *directory* and return a list of per-file row lists.

    Files are kept separate because each carved file is an independent log
    fragment — patterns must never match across file boundaries. Processing
    per-file also bounds the stream size to the largest single file, which
    is essential for performance on large directory corpora.
    """
    files = [p for p in directory.glob("*") if p.is_file()]
    print(f"[*] Found {len(files)} file(s) in {directory}")

    corpus = []
    for filepath in files:
        try:
            rows = read_file(filepath, encoding, confidence_threshold, silent=True)
            if rows:
                corpus.append(rows)
        except Exception as exc:
            print(f"[WARN] Could not read {filepath.name}: {exc}")
    return corpus


# ---------------------------------------------------------------------------
# Path decomposition
# ---------------------------------------------------------------------------

def _file_extension(filename: str) -> str:
    """Return the uppercase extension (without dot), or an empty string."""
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].upper()
    return ext if len(ext) <= 5 else ""


def decompose_path(full_path: str) -> Optional[PathComponents]:
    """Decompose a Windows or UNC path into its forensic components."""
    if not full_path:
        return None

    parts     = full_path.replace("\\", "/").split("/")
    filename  = parts[-1] if parts else ""
    directory = "/".join(parts[:-1]) if len(parts) > 1 else ""

    source_drive = ""
    if len(full_path) >= 2:
        if full_path[1] == ":":
            source_drive = full_path[0].upper() + ":"
        elif full_path.startswith(("\\\\", "//")):
            unc = full_path.lstrip("\\/").split("\\")
            if len(unc) >= 2:
                source_drive = f"\\\\{unc[0]}\\{unc[1]}"

    return PathComponents(
        full_path=full_path,
        filename=filename,
        extension=_file_extension(filename),
        directory=directory.replace("/", "\\"),
        source_drive=source_drive,
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _join_stream(rows: list[str]) -> str:
    """
    Join rows into a single string for stream-dependent pattern matching.

    X-Ways exports search hits at a fixed context width (~98 chars), wrapping
    long log lines across multiple consecutive rows. Joining reconstructs the
    original log content so that patterns spanning multiple rows can match.
    Each row is rstripped before joining to avoid double-space artefacts at
    wrap boundaries inside file paths.
    """
    return " ".join(r.rstrip() for r in rows)


def _parse_rows(rows: list[str], results: ParsedResults) -> None:
    """
    Extract all evidence from one file's rows, accumulating into *results*.

    Stream patterns run against the joined stream; row patterns run against
    individual rows. See module-level pattern comments for the reasoning.
    """
    stream = _join_stream(rows)

    for m in _PAT_VERIFIED.finditer(stream):
        path = m.group(1).strip()
        if path:
            results.verified_paths.add(path)

    for m in _PAT_SIZE.finditer(stream):
        path = m.group(1).strip()
        if path and path not in results.size_map:
            results.size_map[path] = int(m.group(2))

    for row in rows:
        for m in _PAT_ENDPOINT.finditer(row):
            results.endpoints.add(m.group(1).lower())

        for m in _PAT_IP.finditer(row):
            results.ips.add(m.group(1))

        for m in _PAT_DENIED.finditer(row):
            filename = m.group(1).strip()
            if filename:
                results.denied.add(filename)

        if _PAT_ERROR.search(row) and not _PAT_DENIED_GUARD.search(row):
            for m in _PAT_FAILED.finditer(row):
                path = m.group(1).strip()
                if path:
                    results.failed.add(path)

        for m in _PAT_SUBTRANSFER.finditer(row):
            results.subtransfers.add((int(m.group(1)), int(m.group(2))))


def parse(rows: list[str]) -> ParsedResults:
    """Parse a single file's rows and return the results."""
    results = ParsedResults()
    _parse_rows(rows, results)
    return results


def parse_corpus(corpus: list[list[str]]) -> ParsedResults:
    """Parse a directory corpus, processing each file independently."""
    results = ParsedResults()
    for file_rows in corpus:
        _parse_rows(file_rows, results)
    return results


# ---------------------------------------------------------------------------
# CSV output helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _bytes_to_mb(n: int) -> float:
    return round(n / (1024 * 1024), 3)


def _open_csv(path: Path):
    """Open a CSV for writing with a UTF-8 BOM (required for correct Excel import)."""
    return open(path, "w", newline="", encoding="utf-8-sig")


def _write_header(writer, title: str, evidence_basis: str, stats: dict) -> None:
    """Write the standard metadata block that opens every output CSV."""
    writer.writerow([title])
    writer.writerow(["Generated", _now()])
    writer.writerow(["Evidence basis", evidence_basis])
    for label, value in stats.items():
        writer.writerow([label, value])
    writer.writerow([])


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def write_confirmed_uploads(results: ParsedResults, outdir: Path) -> int:
    paths      = sorted(results.verified_paths)
    sized      = sum(1 for p in paths if p in results.size_map)
    total_gb   = sum(results.size_map.get(p, 0) for p in paths) / (1024 ** 3)
    max_queued = max((t for _, t in results.subtransfers), default=0)

    print(f"[*] Confirmed uploads           : {len(paths):,}")
    print(f"[*] Files with size data        : {sized:,}")
    print(f"[*] Total volume (sized files)  : {total_gb:.3f} GB")
    if max_queued:
        print(f"[*] Max files queued (scope)    : {max_queued:,}")

    stats = {
        "Total confirmed uploads":          len(paths),
        "Files with size data":             sized,
        "Minimum confirmed volume (GB)":    f"{total_gb:.3f}",
    }
    if max_queued:
        stats["Total files queued by MEGAsync"] = f"{max_queued:,}"
        stats["Coverage note"] = (
            f"Confirmed list represents records that survived in unallocated "
            f"space. True transfer count may exceed {len(paths):,}."
        )

    outpath = outdir / OUT_CONFIRMED
    with _open_csv(outpath) as f:
        w = csv.writer(f)
        _write_header(
            w,
            title="MEGASYNC CONFIRMED EXFILTRATION — VERIFIED UPLOADS",
            evidence_basis=(
                "Verifying upload: entries anchored to [transfer.cpp — MEGAsync's "
                "own post-delivery confirmation. Each record represents a file "
                "confirmed as successfully received by the MEGA server."
            ),
            stats=stats,
        )
        w.writerow([
            "FullPath", "FileName", "FileExtension", "DirectoryPath",
            "SourceDrive", "SizeMB", "SizeBytes", "SizeConfidence", "TransferConfirmed",
        ])
        for path in paths:
            pc         = decompose_path(path)
            size_bytes = results.size_map.get(path)
            if not pc:
                continue
            w.writerow([
                pc.full_path,
                pc.filename,
                pc.extension,
                pc.directory,
                pc.source_drive,
                _bytes_to_mb(size_bytes) if size_bytes is not None else "",
                size_bytes if size_bytes is not None else "",
                "Confirmed from log" if size_bytes is not None else "Not recovered",
                "Yes",
            ])

    print(f"[*] Written → {outpath}")
    return len(paths)


def write_access_denied(results: ParsedResults, outdir: Path) -> int:
    denied = sorted(results.denied)
    print(f"[*] Access denied files         : {len(denied):,}")

    outpath = outdir / OUT_DENIED
    with _open_csv(outpath) as f:
        w = csv.writer(f)
        _write_header(
            w,
            title="MEGASYNC ACCESS DENIED FILES",
            evidence_basis=(
                "Transfer (UPLOAD) finished with error: Access denied File: entries. "
                "Files were queued for upload but could not be read, likely because "
                "they were open or permission-restricted at transfer time."
            ),
            stats={
                "Total access denied files": len(denied),
                "Path availability": (
                    "Filename only — full source paths are not recorded in this "
                    "log entry type. These files represent intended targets that "
                    "were not successfully exfiltrated."
                ),
            },
        )
        w.writerow(["FileName", "FileExtension", "TransferConfirmed", "Note"])
        for filename in denied:
            w.writerow([
                filename,
                _file_extension(filename),
                "No — Access Denied",
                "Full path not available in this log entry type",
            ])

    print(f"[*] Written → {outpath}")
    return len(denied)


def write_failed_transfers(results: ParsedResults, outdir: Path) -> int:
    failed = sorted(results.failed)
    print(f"[*] Failed transfers            : {len(failed):,}")

    outpath = outdir / OUT_FAILED
    with _open_csv(outpath) as f:
        w = csv.writer(f)
        _write_header(
            w,
            title="MEGASYNC FAILED TRANSFERS",
            evidence_basis=(
                "transfer->name entries in rows containing 'finished with error', "
                "excluding Access Denied failures. Files were queued and attempted "
                "but did not complete due to a general error condition."
            ),
            stats={"Total failed transfers": len(failed)},
        )
        w.writerow([
            "FullPath", "FileName", "FileExtension",
            "DirectoryPath", "SourceDrive", "TransferConfirmed",
        ])
        for path in failed:
            pc = decompose_path(path)
            if not pc:
                continue
            w.writerow([
                pc.full_path, pc.filename, pc.extension,
                pc.directory, pc.source_drive, "No — Transfer Failed",
            ])

    print(f"[*] Written → {outpath}")
    return len(failed)


def write_endpoints(results: ParsedResults, outdir: Path) -> tuple[int, int]:
    endpoints = sorted(results.endpoints)
    ips       = sorted(results.ips)

    print(f"[*] MEGA endpoints              : {len(endpoints):,}")
    print(f"[*] Resolved IPs               : {len(ips):,}")

    outpath = outdir / OUT_ENDPOINTS
    with _open_csv(outpath) as f:
        w = csv.writer(f)
        _write_header(
            w,
            title="MEGASYNC UPLOAD ENDPOINTS",
            evidence_basis=(
                "Hostnames extracted from CURLMSG_DONE log entries. These servers "
                "physically received the exfiltrated data. Pattern validated against "
                "the known MEGA CDN naming convention: "
                "gfs[datacenter]n[node].userstorage.mega.co.nz."
            ),
            stats={"Total unique endpoints": len(endpoints)},
        )
        w.writerow(["Hostname", "Domain", "Note"])
        for ep in endpoints:
            w.writerow([ep, "userstorage.mega.co.nz", "Validated MEGA upload endpoint"])

    print(f"[*] Written → {outpath}")

    outpath_ips = outdir / OUT_IPS
    with _open_csv(outpath_ips) as f:
        w = csv.writer(f)
        _write_header(
            w,
            title="MEGASYNC RESOLVED IP ADDRESSES",
            evidence_basis=(
                "IP addresses extracted from CURLMSG_DONE log lines containing "
                "mega.co.nz hostnames. These are the addresses to which the "
                "exfiltrated data was physically transmitted."
            ),
            stats={"Total unique IPs": len(ips)},
        )
        w.writerow(["IPAddress", "Note"])
        for ip in ips:
            w.writerow([ip, "Extracted from CURLMSG_DONE — mega.co.nz context"])

    print(f"[*] Written → {outpath_ips}")
    return len(endpoints), len(ips)


# ---------------------------------------------------------------------------
# Investigation summary
# ---------------------------------------------------------------------------

def write_summary(outdir: Path, counts: tuple[int, int, int, int, int]) -> None:
    """Write a plain-text cover sheet combining all findings for legal counsel."""
    confirmed, denied, failed, endpoints, ips = counts
    sep  = "=" * 70
    dash = "-" * 70

    outpath = outdir / OUT_SUMMARY
    with open(outpath, "w", encoding="utf-8") as f:

        f.write(f"{sep}\nMEGASYNC EXFILTRATION — INVESTIGATION SUMMARY\n")
        f.write(f"Generated: {_now()}\n{sep}\n\n")

        f.write(f"FINDINGS OVERVIEW\n{dash}\n")
        f.write(f"Confirmed exfiltrated files    : {confirmed:,}\n")
        f.write(f"Access denied (targeted)       : {denied:,}\n")
        f.write(f"Failed transfers               : {failed:,}\n")
        f.write(f"Unique MEGA upload endpoints   : {endpoints:,}\n")
        f.write(f"Unique destination IPs         : {ips:,}\n\n")

        f.write(f"OUTPUT FILES\n{dash}\n")
        for filename, description in [
            (OUT_CONFIRMED, "Confirmed exfiltrated files"),
            (OUT_DENIED,    "Files targeted but unreadable"),
            (OUT_FAILED,    "Files with general transfer errors"),
            (OUT_ENDPOINTS, "MEGA upload servers"),
            (OUT_IPS,       "Destination IP addresses"),
        ]:
            f.write(f"{filename:<35} {description}\n")
        f.write("\n")

        f.write(f"EVIDENCE BASIS\n{dash}\n")
        f.write(
            "All data was extracted from MEGAsync application log content\n"
            "recovered from unallocated disk space on the forensic image.\n"
            "The log file itself was not present in the active file system.\n"
            "Log fragments survived in the slack space of previously existing\n"
            "files located in unallocated regions of the disk.\n\n"
        )

        f.write(f"INTERPRETATION NOTES FOR COUNSEL\n{dash}\n")
        f.write(
            "1. CONFIRMED FILES: Every file in confirmed_uploads.csv was verified\n"
            "   by MEGAsync's own post-delivery confirmation step — the highest\n"
            "   available evidence standard from this log source. The count is a\n"
            "   minimum: log fragments that did not survive in unallocated space\n"
            "   are not represented.\n\n"
            "2. ACCESS DENIED FILES: These were targeted by the exfiltration tool\n"
            "   but could not be read, most likely because they were open by\n"
            "   another process at the time. They represent intended scope beyond\n"
            "   what was successfully transferred.\n\n"
            "3. FAILED TRANSFERS: General errors distinct from access denied.\n"
            "   These files were queued and attempted but did not complete.\n\n"
            "4. SIZE DATA: File sizes are recovered where the fingerprint log entry\n"
            "   appeared in the same recovered fragment as the verification record.\n"
            "   Where absent, SizeConfidence is marked 'Not recovered' — this does\n"
            "   not indicate the file was not transferred.\n"
        )
        f.write(f"{sep}\n")

    print(f"[*] Summary → {outpath}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_common_encodings() -> None:
    encodings = [
        ("utf-8",     "UTF-8 (no BOM) — standard default"),
        ("utf-8-sig", "UTF-8 with BOM — common in Windows exports"),
        ("utf-16",    "UTF-16 with BOM — XWF TSV default"),
        ("utf-16-le", "UTF-16 Little Endian (explicit, no BOM)"),
        ("utf-16-be", "UTF-16 Big Endian (explicit, no BOM)"),
        ("cp1252",    "Windows-1252 — Western European Windows"),
        ("latin-1",   "ISO 8859-1 — permissive Western European"),
        ("ascii",     "ASCII only — 7-bit clean"),
    ]
    print("\nCommon encodings for --encoding:\n")
    for name, description in encodings:
        print(f"  {name:<16}  {description}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="MegaParser",
        description="MEGAsync log extractor — CSV output for legal counsel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Encoding\n"
            "--------\n"
            "  Encoding is auto-detected by BOM inspection first (covers all\n"
            "  XWF TSV exports), then by charset-normalizer for plaintext files.\n"
            "  Use --encoding to bypass detection when the encoding is known.\n\n"
            "Examples\n"
            "--------\n"
            "  python MegaParser.py --input search_hits.tsv\n"
            "  python MegaParser.py --inputdir C:\\extracted\\files\n"
            "  python MegaParser.py --input hits.tsv --outdir C:\\output\n"
            "  python MegaParser.py --input hits.tsv --encoding utf-16\n"
            "  python MegaParser.py --list-encodings\n"
        ),
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input",    metavar="FILE", help="Single XWF TSV/text export file")
    source.add_argument("--inputdir", metavar="DIR",  help="Directory of XWF exported plaintext files")

    parser.add_argument(
        "--outdir", default=".", metavar="DIR",
        help="Output directory for CSV files (default: current directory)",
    )
    parser.add_argument(
        "--encoding", default=None, metavar="CODEC",
        help="Force a specific encoding, e.g. utf-8, utf-16, cp1252. Skips auto-detection.",
    )
    parser.add_argument(
        "--encoding-confidence", dest="encoding_confidence",
        type=float, default=DEFAULT_CONFIDENCE_THRESHOLD, metavar="0.0-1.0",
        help=(
            f"Minimum confidence for charset-normalizer encoding detection. "
            f"Below this threshold the script falls back to {ENCODING_FALLBACK}. "
            f"(default: {DEFAULT_CONFIDENCE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--list-encodings", action="store_true",
        help="Print common encoding names and exit.",
    )
    return parser


def main() -> None:
    if "--list-encodings" in sys.argv:
        _print_common_encodings()
        sys.exit(0)

    parser = build_parser()
    args   = parser.parse_args()

    if not 0.0 <= args.encoding_confidence <= 1.0:
        parser.error("--encoding-confidence must be between 0.0 and 1.0")

    outdir = Path(args.outdir)
    if not outdir.exists():
        print(f"[ERROR] Output directory not found: {args.outdir}")
        sys.exit(1)

    if args.inputdir:
        input_dir = Path(args.inputdir)
        if not input_dir.is_dir():
            print(f"[ERROR] Input directory not found: {args.inputdir}")
            sys.exit(1)
        corpus     = read_directory(input_dir, args.encoding, args.encoding_confidence)
        total_rows = sum(len(f) for f in corpus)
        print(f"[*] Loaded {total_rows:,} rows across {len(corpus)} file(s)")
        print(f"[*] Output directory: {outdir.resolve()}\n")
        print("[*] Parsing ...")
        results = parse_corpus(corpus)
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[ERROR] Input file not found: {args.input}")
            sys.exit(1)
        rows = read_file(input_path, args.encoding, args.encoding_confidence)
        print(f"[*] Loaded {len(rows):,} rows")
        print(f"[*] Output directory: {outdir.resolve()}\n")
        print("[*] Parsing ...")
        results = parse(rows)

    print()
    confirmed        = write_confirmed_uploads(results, outdir);  print()
    denied           = write_access_denied(results, outdir);      print()
    failed           = write_failed_transfers(results, outdir);   print()
    endpoints, ips   = write_endpoints(results, outdir);          print()
    write_summary(outdir, (confirmed, denied, failed, endpoints, ips))

    print(f"\n{'=' * 50}")
    print(f"  Confirmed uploads  : {confirmed:,}")
    print(f"  Access denied      : {denied:,}")
    print(f"  Failed transfers   : {failed:,}")
    print(f"  MEGA endpoints     : {endpoints:,}")
    print(f"  Destination IPs    : {ips:,}")
    print(f"{'=' * 50}")
    print("[*] Complete")


if __name__ == "__main__":
    main()
