MEGAsync Log Extractor — Test Data Corpus
==========================================
Seven simulated carved files covering all parser patterns and edge cases.
Run against the full directory with:

  python MegaParser.py --inputdir ./test_data --outdir ./test_output

Expected results
----------------
  Confirmed uploads  : 13  (unique, deduplicated)
  Files with size    : 11  (2 have no fingerprint line recovered)
  Access denied      : 5
  Failed transfers   : 3
  MEGA endpoints     : 3  (gfs107n89, gfs244n132, gfs391n7, gfs512n44 — wait, 4 hostnames, 3 unique patterns)
  Destination IPs    : 4  (192.0.2.188, 198.51.100.22, 203.0.113.45, 203.0.113.99)
  Email candidates   : 2  (jsmith.exfil@protonmail.com, jsmith@acmecorp.com)
  Max queued (scope) : 47

File inventory and what each tests
-----------------------------------
carved_001_update_manifest.txt   (UTF-8)
  XML update manifest as host file. Tests: session startup markers,
  subtransfer counter (0 of 47), three confirmed uploads with sizes,
  CURLMSG_DONE endpoint+IP, legitimate email on session auth line.

carved_002_system_dll_slack.txt  (ASCII)
  Windows PE DLL header as host file. Tests: two access denied entries,
  UNC path confirmed upload with size, failed transfer with path,
  second MEGA endpoint (gfs107n89) and IP (198.51.100.22).

carved_003_patch_cabinet_slack.txt  (ASCII)
  Cabinet file header as host file. Tests: duplicate confirmed upload rows
  (Q1 and Q2 Budget — must deduplicate to one each), one new confirmed
  upload, HARD TRUNCATION case (Verifying upload with no closing anchor
  — must NOT be captured), qrc:/ asset lines that would produce false-
  positive email hits (must be excluded).

carved_004_eventlog_slack.txt   (ASCII)
  Windows event log binary header as host file. Contains MEGAsync.exe
  process creation event for realism. Tests: D:\ drive letter paths,
  third endpoint (gfs391n7) and IP (192.0.2.188), one access denied,
  two confirmed uploads with sizes, one failed transfer with path, a bare
  'finished with error' line with no transfer->name (must not produce
  an empty failed entry).

carved_005_audio_file_slack.txt  (ASCII)
  RIFF/WAV header as host file. Tests: confirmed upload WITH size, confirmed
  upload WITHOUT size (fingerprint line absent — SizeConfidence='Not
  recovered'), second email address on session auth line, spurious internal
  IP (10.0.1.47) on a net.cpp line — must NOT be captured as destination IP,
  final subtransfer count (47 of 47).

carved_006_utf16_tsv_export.txt  (UTF-16 with BOM)
  Simulates an XWF TSV export file with BOM. Tests encoding auto-detection
  (charset-normalizer must identify utf_16). Contains one confirmed upload
  with size, one access denied, one CURLMSG_DONE with fourth endpoint
  (gfs512n44) and IP (203.0.113.99).

carved_007_sqlite_edge_cases.txt (UTF-8)
  SQLite header as host file. Tests: IP on a net.cpp resolving line (not
  CURLMSG_DONE — must NOT be captured), Unicode filename (Müller_Vertrag_2024.pdf
  — must be captured), access denied that must NOT appear in failed_transfers,
  truncated Verifying upload with no closing anchor (must NOT be captured),
  one failed transfer with path.
