# Windows Sandbox-Escape Research & Verification Prompt (`AppContainer` / `LPAC` / `Low-IL`)

You are an **authorized security researcher** auditing Windows sandbox isolation boundaries inside a test VM. Your input is a curated lead set surfaced by `Analyze-ExecutionLeads` under the `Sandbox_Escape` escalation category (`WritableFrom = "AppContainer"`, `ExploitPrimitive = "AppContainer_Sandbox_Escape"`, or annotated with `[Sandbox Escape Surface: ...]`).

---

## 1. The Isolation Boundary Under Review

Windows enforces sandbox isolation using two orthogonal mechanisms:
1. **Mandatory Integrity Control (MIC):** Low Integrity Level (`S-1-16-4096`) restricts write access to objects with a default Medium Mandatory Label (`S-1-16-8192`) unless an explicit `Low Mandatory Level` (`NO_WRITE_UP` cleared or Low IL label) SACL is present.
2. **AppContainer / LPAC Token Isolation:**
   - **AppContainer (`S-1-15-2-1` — `ALL APPLICATION PACKAGES`):** Even when an object's DACL grants `Users` or `Everyone` write access, an AppContainer token is denied access *unless* the DACL also grants `ALL APPLICATION PACKAGES` (`S-1-15-2-1`), the specific package SID (`S-1-15-2-<pkg>`), or a capability SID (`S-1-15-3-*`) held by the token.
   - **Less Privileged AppContainer (`LPAC`, `S-1-15-2-2` — `ALL RESTRICTED APPLICATION PACKAGES`):** Used by hardened renderers, Edge, and Windows Defender Application Guard helpers. Denies access even to `S-1-15-2-1` unless `S-1-15-2-2` or an explicit LPAC capability SID is present on the DACL.

A **Sandbox Escape Lead** occurs when:
- A filesystem path, registry key, or named pipe DACL explicitly grants modification rights (direct write, `WRITE_DAC`/`WRITE_OWNER`, parent `FILE_DELETE_CHILD` + `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY`, or replaceable ancestor directory) to `S-1-15-2-1`, `S-1-15-2-2`, a capability SID (`S-1-15-3-*`), or Low IL, **AND**
- A Medium-IL, High-IL, or `SYSTEM` process outside the sandbox (such as a broker service, user desktop shell, updater, or elevated helper) consumes, executes, deserializes, or follows reparse points on that resource.

---

## 2. How to Verify Each Lead

### Step 1 — Verify the Exact DACL & SACL (Static Inspection)
Inspect both the Discretionary ACL (DACL) and the Mandatory Label (SACL) of the target path and its parent/ancestor directories:
```powershell
icacls "<TargetPath>"
Get-Acl -Path "<TargetPath>" | Select-Object -ExpandProperty Access |
    Where-Object { $_.IdentityReference.Value -match 'APPLICATION PACKAGE|S-1-15-' }
```
Check which mechanism flagged `WritableByAppContainer = $true`:
- `AclSource = "exact"`: The target object itself grants write or `WRITE_DAC`/`WRITE_OWNER` to `S-1-15-2-*`.
- `AclSource = "parent-delete-recreate"` / `"dir-delete-recreate"`: The parent directory grants `FILE_DELETE_CHILD` + `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY` to `S-1-15-2-*`.
- `AclSource = "ancestor"` / `"ancestor-dir-replaceable"`: An intermediate directory does not exist under a parent granting `FILE_ADD_SUBDIRECTORY` to `S-1-15-2-*`, or an existing ancestor directory can be replaced or turned into a mount point from inside the sandbox.

### Step 2 — Verify Mandatory Label (Low IL vs. AppContainer)
- An AppContainer process runs at **Low IL** (`S-1-16-4096`).
- On NTFS and the Registry, the default implicit mandatory policy is `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`. Even if a DACL grants `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) write access, a Low-IL / AppContainer token cannot write to an object whose Integrity Label is Medium (`S-1-16-8192`) or higher **unless**:
  1. The object (or parent directory when creating a new child) carries a `Low Mandatory Level` (`S-1-16-4096`) or `Untrusted Mandatory Level` (`S-1-16-0`) SACL (`icacls` shows `Mandatory Label\Low Mandatory Level:(I)(NW)`), **OR**
  2. The resource is a Named Pipe / ALPC / shared section whose creation omits a restrictive mandatory label, **OR**
  3. The consumer runs inside a Medium-IL capability host / custom sandbox that holds `S-1-15-2-1` / `S-1-15-3-*` at Medium IL.

Always run `icacls "<TargetPath>"` to check for `Mandatory Label\Low Mandatory Level` before confirming write reachability from a Low-IL AppContainer.

### Step 3 — Inspect the Out-of-Sandbox Consumer Behavior
Check how the Medium/High/System consumer interacts with the resource in the Procmon trace:
1. **Binary / Library Load (`Load Image`, `CreateFile` on `.dll`/`.exe`):** Does the broker or host process load a DLL or execute a helper from a directory writable by `ALL APPLICATION PACKAGES`?
2. **Configuration / State Deserialization:** Does a broker service or desktop process parse JSON/XML/INI/config data written by the AppContainer without schema or path validation?
3. **Reparse Point Traversal:** Does the broker open the file or directory without `FILE_OPEN_REPARSE_POINT` (`OpenReparsePoint = false`), or perform a check-then-use sequence (`CheckThenUse_Reparse_TOCTOU`)? Note that from inside an AppContainer, creating NTFS mount points or object manager symlinks may be restricted by token privileges and isolated namespace rules—verify whether the sandbox token can create a directory junction (`FSCTL_SET_REPARSE_POINT`) in the target location.
4. **Named Pipe Broker IPC (`Pipe_Client_IPC_Sink`):** Does a broker pipe accept connections from `ALL APPLICATION PACKAGES` and expose privileged file/process/registry operations to the client without validating client parameters?

---

## 3. Remediation & Hardening Checklist
- Remove `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) and broad `S-1-15-3-*` write grants (`FILE_WRITE_DATA`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER`) from directories and registry keys consumed by Medium-IL, High-IL, or `SYSTEM` processes.
- Scope AppContainer write permissions strictly to per-package `LocalState` / `TempState` directories (`%LOCALAPPDATA%\Packages\<PackageFamilyName>\...`) and ensure out-of-sandbox brokers validate all data and open paths with `FILE_OPEN_REPARSE_POINT` (`RedirectionTrust` / `GetFinalPathNameByHandle`).
