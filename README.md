# MegaParser

A forensic extraction tool for recovering MEGAsync exfiltration evidence from unallocated disk space. Processes plaintext and TSV exports from X-Ways Forensics and produces structured CSV output suitable for Excel workbook assembly and presentation to legal counsel.

**Background:** This tool was developed during an active incident response engagement to recover MEGA transfer evidence in the absence of application logs. A full write-up of the methodology is available on [LinkedIn](https://www.linkedin.com/). <!-- update with your post URL -->

---

## The Problem It Solves

When a threat actor removes MEGAsync after an exfiltration event, the application log is gone — but the log content that existed in process memory during the transfer session may have been paged to disk by the Windows memory manager. Those paged memory contents persist in unallocated disk space until overwritten by subsequent activity. If the system is imaged in time, the log fragments are recoverable.

MegaParser takes the search hit exports from an X-Ways unallocated space search and extracts structured evidence from those fragments: confirmed file transfers, access denied attempts, failed transfers, upload endpoints, and resolved IP addresses.

---

## Output Files

| File | Contents |
|---|---|
| `confirmed_uploads.csv` | Files confirmed delivered by MEGAsync's own post-delivery verification step. Highest-confidence evidence. |
| `access_denied.csv` | Files targeted by the exfiltration tool but unreadable at transfer time. Represents intended scope. |
| `failed_transfers.csv` | Files queued and attempted but not completed due to general errors. |
| `mega_endpoints.csv` | MEGA CDN upload hostnames and account email candidates for manual review. |
| `mega_ips.csv` | Resolved IP addresses of MEGA upload servers extracted from completed transfer records. |
| `investigation_summary.txt` | Plain-text cover sheet combining all findings, with interpretation notes for legal counsel. |

---

## Installation

Python 3.8 or later is required.

```bash
git clone https://github.com/The-DFIR-Reference/MegaParser.git
cd MegaParser
pip install charset-normalizer
```

`charset-normalizer` is the only external dependency. It handles encoding auto-detection and is widely available.

---

## Usage

**Single file input** (XWF TSV or plaintext export):
```bash
python MegaParser.py --input search_hits.tsv
```

**Directory input** (multiple exported files):
```bash
python MegaParser.py --inputdir C:\extracted\files
```

**Specify output directory:**
```bash
python MegaParser.py --input search_hits.tsv --outdir C:\case\output
```

**Force a specific encoding** (bypasses auto-detection):
```bash
python MegaParser.py --input search_hits.tsv --encoding utf-16
```

**Raise the auto-detection confidence threshold:**
```bash
python MegaParser.py --input search_hits.tsv --encoding-confidence 0.9
```

**List common encoding names:**
```bash
python MegaParser.py --list-encodings
```

---

## Encoding Handling

By default, MegaParser auto-detects the encoding of each input file using `charset-normalizer`, inspecting a 64 KB sample before reading. This handles the mixed-encoding reality of multi-file extractions: XWF TSV exports are typically UTF-16 with BOM, while plaintext carved files are often UTF-8 or ASCII.

When auto-detection confidence falls below the threshold (default: 70%), the script warns and falls back to UTF-8 rather than silently producing garbage. Use `--encoding` to bypass detection entirely when you know the source encoding.

In `--inputdir` mode, each file is detected independently, which handles directories containing files of different encodings without any manual intervention.

---

## X-Ways Search Configuration

The tool is designed to process output from an X-Ways Forensics simultaneous search scoped to unallocated space. The following search terms should be used to generate the source data:

```
Verifying upload:
Upload complete:
transferring:
FA debug fp:
finished with error
Access denied File:
MegaRecursiveOperation finished subtransfers:
CURLMSG_DONE
userstorage.mega.co.nz
MegaClient::login
session resume
megaclient_statecache
MEGAsync
Transferring:
Transferred:
```

Export search hits as plaintext (one context per row). The context window should be wide enough to capture both the `Verifying upload:` line and the immediately following `FA debug fp:` fingerprint line on the same exported row — this is required for file size recovery.

---

## Evidence Interpretation

### Confirmed Uploads

Every entry in `confirmed_uploads.csv` is anchored to a `Verifying upload:` log entry — MEGAsync's own post-delivery confirmation after the MEGA server has acknowledged receipt. This is not a record of a transfer attempt; it is the application's own receipt. It represents the highest-confidence evidence available from this log source.

The confirmed list is a **minimum count**, not a ceiling. Log fragments that did not survive in unallocated space are not represented.

### File Sizes

Sizes are recovered where the `FA debug fp:` fingerprint entry appeared within the same recovered context row as the verification record. Where absent, `SizeConfidence` is marked `Not recovered`. This does not indicate the file was not transferred.

### Access Denied Files

These files were targeted by the exfiltration tool but could not be read — most likely open by another process at the time. They represent intended scope beyond what was successfully transferred. Full paths are not available in this log entry type; filenames only.

### Email Candidates

Extracted from authentication log entries and require manual review before use in legal documents. The pattern may produce false positives. Confirm against session initiation log context before citing.

### Subtransfer Counters

The maximum `Y` value from `MegaRecursiveOperation finished subtransfers: X of Y` entries indicates the total number of files queued by the exfiltration tool regardless of transfer outcome. This provides a scope indicator that can be compared against the confirmed transfer list.

---

## Testing

A test corpus of seven simulated carved files is included in the `test_data/` directory. These files simulate realistic X-Ways carved output: each file has plausible host file content (Windows update manifests, PE headers, cabinet files, event logs, etc.) with MEGA log fragments in the slack space region.

```bash
mkdir test_output
python MegaParser.py --inputdir test_data --outdir test_output
```

Expected results against the test corpus:

| Metric | Expected |
|---|---|
| Confirmed uploads | 13 (deduplicated across files) |
| Files with size data | 11 |
| Access denied | 5 |
| Failed transfers | 3 |
| MEGA endpoints | 3 |
| Destination IPs | 4 |
| Email candidates | 2 |
| Max files queued | 47 |

The test corpus exercises: duplicate deduplication, truncated `Verifying upload:` lines with no closing anchor (must not match), bare error lines with no transfer path (must not produce empty entries), IPs on non-`CURLMSG_DONE` lines (must not be captured), UNC paths, `D:\` drive paths, Unicode filenames, confirmed uploads with missing fingerprint lines, and UTF-16 BOM encoding auto-detection.

See `test_data/README.txt` for a full breakdown of what each file exercises.

---

## Limitations

This methodology and tool have real constraints that should be communicated to any legal or organizational audience reviewing the output.

**The confirmed file list is a minimum.** Log fragments that did not survive in unallocated space produce no output. The true transfer count is likely higher than what is recovered.

**Timely acquisition matters.** The longer the gap between the exfiltration event and disk imaging, the greater the probability that relevant unallocated clusters have been overwritten by subsequent system activity. Delayed acquisition may produce partial or no recovery.

**Access denied filenames lack full paths.** This is a characteristic of that log entry type, not a recovery failure. These entries establish intended scope but should be clearly distinguished from the confirmed transfer list in formal output.

**This is one component of a broader investigation.** It should be combined with traditional timeline analysis, Windows artifact examination, and network forensics where those artifacts are available.

---

## Contributing

Issues, contributions, and case feedback are welcome. If you have encountered MEGA or similar exfiltration tool artifacts in your own investigations and have suggestions for improving pattern coverage or output structure, please open an issue or submit a pull request.

---

## License

MIT License. See `LICENSE` for details.
