# Portability TODO — host-specific leaks (audit 2026-11-14)

Things that are accidentally specific to the dev machine instead of generic for any Windows host.

## 1. Host-specific artifacts committed to git
- [ ] `7b39ef3-leads.md` — real leads report from the dev host (driver SDDLs, scheduled tasks incl. stray `\Microsoft\Windows\AppxDeploymentClient\MyTaskName -> C:\Path\To\YourApp.exe`). Committed in `9bec9ca`; contradicts `.gitignore` "keep host-specific recon off public history". `git rm --cached` + consider history rewrite if public.
- [ ] `TestTrace.etl` — still tracked despite `*.etl` ignore rule.
- [ ] `183723319.png` — unreferenced stray screenshot.
- [ ] `test_upload.js` — needs a local `ShortDLLTrace.CSV` not in repo; hardcodes `localhost:3000`.
- [ ] `ROADMAP.md` — ~20 `file:///D:/Projects/ProcmonAnalyzer/...` links; make them relative.

## 2. Code assumptions that break on other hosts
- [ ] **Unmapped volume -> `C:` fallback**: `skills/Parse-NativeTrace/scripts/ParseEtwTrace.ps1:196`, `ui/public/NativeTrace.ps1:320` rewrite any `\Device\HarddiskVolumeN` missing from the drive map to `C:\...` even when the map is populated -> wrong ACL target. Leave unresolved / flag instead.
  - `ParseProcmonTraceTestWritablePaths.ps1:340, 1159` only fall back when map is empty (safer, still an assumption).
- [ ] `skills/Enrich-SystemPermissions/scripts/EnrichSystemPermissions.ps1:946, 1025` hardcode `C:\Windows\System32\Tasks`; line 905 correctly uses `$env:SystemRoot`.
- [ ] Defaults `C:\Temp\...` in `CaptureNativeTrace.ps1:5`, `ParseEtwTrace.ps1:2-3` -> use `$env:TEMP` or repo-relative.
- [ ] **Localized account names**: `ParseProcmonTraceTestWritablePaths.ps1:591-593` string-compares `NT AUTHORITY\SYSTEM` / `LOCAL SERVICE` / `NETWORK SERVICE`. Procmon resolves names in the OS locale (e.g. `NT-AUTORITÄT\SYSTEM`) -> SYSTEM impersonation misclassified on non-English Windows. Compare SIDs or the post-backslash token.
  - `EnrichSystemPermissions.ps1:709` same pattern, lower risk (service ObjectName is usually stored in English).
- [ ] Default profile layout assumed (`X:\Users\<name>\...`): `AnalyzeExecutionLeads.ps1:1643`, `ParseProcmonTraceTestWritablePaths.ps1:509, 862-863, 1813-1814`. Relocated profiles / redirected ProgramData misclassify. Probably document rather than fix.

## 3. Undocumented same-host requirement
- [ ] `README.md:92` says "the trace can be captured on any machine", but the parse stage does **live** `Get-Acl` and builds the `HarddiskVolumeN -> letter` map on whatever host runs it. Capture on A + parse on B = ACL verdicts describe B and volume numbers may point at different disks. Either document "parse on the traced host" or snapshot drive map + ACLs at capture time.

## Fine as-is (checked)
- `Test-Analyzer.ps1` synthetic `C:\Users\Alice\...` fixtures.
- Procmon CSV headers / result strings (Procmon isn't localized); tracerpt provider names.
- Rule logic uses well-known SIDs, not group names; no vendor-specific tailoring in rules.
- UI server resolves script paths relative to `__dirname`.
