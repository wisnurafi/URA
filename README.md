# Universal Runtime Analyzer (URA)

A read-only runtime memory analysis framework for Windows applications, written
in C++20. Built as a reverse-engineering study tool — process memory layout,
PE structures, pattern scanning, MSVC RTTI, vtable inference, cross-references,
and engine-specific runtime introspection.

URA opens a target with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and
nothing else. There is no write API anywhere in the codebase. It is meant for
software you own, offline games, open-source applications, crackmes, and
authorized testing environments — not for online games or anti-cheat-protected
processes.

## What's in the box

- **Process attachment** with read-only handle and a graceful fallback to
  `PROCESS_QUERY_LIMITED_INFORMATION` when full QUERY is denied.
- **Architecture detection** via `IsWow64Process2` (with a runtime-resolved
  fallback for older Windows). Reports analyzer / target / native arch
  separately so cross-bitness mismatches are caught up front instead of
  failing 250ms later inside `EnumProcessModulesEx`.
- **Robust module enumeration** — bounded retry, dynamic buffer resize, and an
  evidence-based diagnostic that distinguishes architecture mismatch, access
  denied, loader transitions, partial copies, terminated processes, and
  generic Win32 failures. The previous "looks like anti-cheat, sorry" guess is
  gone.
- **PE parser** for both PE32 and PE32+ images — sections, characteristics,
  Export Address Table (name + ordinal + RVA), forwarder detection.
- **Pattern scanner** with IDA-style byte signatures (`"48 8B 05 ?? ?? ?? ??"`)
  and optional address transforms (RIP-relative-32, absolute-32, absolute-64).
- **Signature loader** — patterns ship as JSON in `data/signatures/<engine>.json`
  so engines fall back gracefully when files are missing.
- **String scanner** for ASCII and UTF-16LE markers across `.rdata` / `.data`.
- **Cross-reference scanner** — small decoder for `CALL/JMP near (E8/E9)`,
  `LEA/MOV r64, [RIP+disp32]`, indirect `CALL/JMP [imm32]`, absolute
  `MOV reg, imm32`, and x86 `PUSH imm32`.
- **MSVC RTTI / vtable scanner** — walks `.rdata` for
  `RTTICompleteObjectLocator` candidates, dereferences `TypeDescriptor`,
  recovers mangled names, best-effort demangles them, and counts vtable slots.
- **Memory region map** via `VirtualQueryEx` — every committed/reserved region
  with state, protection, type. Flags RWX and executable `MEM_PRIVATE` regions
  as anomalies (classic JIT / injection signals).
- **Static fallback** — when live acquisition fails but the executable path is
  known, URA inspects the PE file on disk, dumps every section + named export
  with RVAs, and writes the result to JSON anyway. Use `--static-pe <path>`
  for pure offline analysis with no process attach at all.
- **JSON exporter** with versioned schema (`schema_version: "1"`) covering
  process, modules, groups, classes, memory map, acquisition diagnostic,
  optional static block, notes, and warnings.
- **Two frontends** — a CLI (`URA.exe ...`) and a Dear ImGui + DirectX 11 GUI.
  Double-clicking `URA.exe` opens the GUI. The CLI is opt-in via flags.

## What's not in the box

- Writing remote process memory.
- DLL injection or thread hijacking.
- Bypassing, evading, or interacting with anti-cheat systems.
- Patching, hooking, or modifying game logic.
- Kernel mode anything.

`MemoryReader` exposes no write API. `ProcessHandle::open_for_read` is the
only factory and never asks for `PROCESS_VM_WRITE` / `PROCESS_VM_OPERATION`.

## Supported targets

| Target              | Engine module          | Status                            |
| ------------------- | ---------------------- | --------------------------------- |
| Counter-Strike 1.6  | `GoldSrcEngine`        | Verified end-to-end               |
| Generic native exe  | `GenericNativeEngine`  | Verified                          |
| Goose Goose Duck    | `UnityIL2CPPEngine`    | EAC blocks read; ethical refusal  |
| Among Us            | `UnityIL2CPPEngine`    | Skeleton                          |
| Source engine games | `SourceEngine`         | Skeleton                          |

## Build

- Visual Studio 2022, MSVC v143, C++20, Windows 10 SDK.
- Both `x64` and `x86` configurations supported. Use **x64** unless you have a
  specific 32-bit target — running x86 URA against a 64-bit target is rejected
  up front with a clear `ArchitectureMismatch` diagnostic.
- Drop [`nlohmann/json.hpp`](https://github.com/nlohmann/json/releases) into
  `UniversalRuntimeAnalyzer/third_party/nlohmann/json.hpp` if not already
  vendored.
- Drop [Dear ImGui](https://github.com/ocornut/imgui) into
  `UniversalRuntimeAnalyzer/third_party/imgui/` if not already vendored
  (top-level files plus
  `backends/imgui_impl_win32.{h,cpp}` and `backends/imgui_impl_dx11.{h,cpp}`).
- Open `UniversalRuntimeAnalyzer.sln` and build, or from the command line:

  ```text
  msbuild UniversalRuntimeAnalyzer.sln /p:Configuration=Release /p:Platform=x64
  ```

Output: `x64\Release\URA.exe` (or `Release\URA.exe` for the x86 build).

## Running

**Just want the GUI?** Double-click `URA.exe`. The console window won't appear.

**CLI**:

```text
URA.exe --gui                                       # explicit GUI launch
URA.exe --list-engines
URA.exe --list-processes
URA.exe --pid 1234 --auto                           # auto-detect engine
URA.exe --pid 1234 --engine generic_native --out r.json
URA.exe --process hl.exe --engine goldsrc --out cs16.json --verbose
URA.exe --static-pe "C:\path\to\file.exe" --out static.json
```

The GUI presents a process picker, engine selector, and tabs for diagnostics,
modules, groups (resolved offsets), the address-space memory map, recovered
RTTI classes, notes, and the raw JSON export.

## Acquisition diagnostic

Every Analyze run produces a structured diagnostic, not a free-form error
string. The diagnostic is rendered as a multi-line block on the CLI and as
the **Diagnostics** tab in the GUI. Fields:

- `status` — one of `Success`, `ArchitectureMismatch`, `AccessDenied`,
  `LoaderTransition`, `PartialCopy`, `ProcessTerminated`,
  `ModuleEnumerationFailed`, `MemoryReadRestricted`, `ProtectedOrRestricted`,
  `OpenProcessFailed`, `ProcessNotFound`, `UnsupportedArchitecture`, or
  `UnknownFailure`.
- Three architecture fields: analyzer, target, native OS.
- Stage flags: handle opened, query succeeded, enumeration succeeded, memory
  read succeeded.
- `enumeration_attempts`, `failed_api`, `failed_stage`, `win32_error`,
  `details`, `recommended_action`.

The same data ends up in JSON under the top-level `acquisition` object.
Downstream tools should branch on `status` instead of grepping warning strings.

## CLI exit codes

| Code | Meaning                             |
| ---- | ----------------------------------- |
| 0    | Success                             |
| 2    | Process not found                   |
| 3    | OpenProcess failed / access denied  |
| 4    | Module enumeration failed (or kin)  |
| 8    | JSON export failed                  |
| 9    | Architecture mismatch (pre-flight)  |
| 64   | Bad arguments                       |

## JSON output (v1, abridged)

```json
{
  "tool":     { "name", "version", "schema_version", "generated_at" },
  "engine":   { "id", "display_name", "duration_ms" },
  "process":  { "pid", "name", "path", "is_wow64", "bitness",
                "architecture", "analyzer_architecture", "native_architecture" },
  "modules":  [ { "name", "base", "size_of_image", "sections":[...] } ],
  "groups":   [ { "name": "<engine>.<group>",
                  "offsets":[ { "label", "absolute", "rva", "module", "notes" } ] } ],
  "classes":  [ { "demangled", "mangled", "module", "vftable", "vftable_rva",
                  "method_count", "inheritance_offset" } ],
  "memory_map": {
      "summary":   { "total_regions", "committed", "rwx", "image_regions",
                     "mapped_regions", "private_regions",
                     "total_committed_bytes" },
      "anomalies": [ "16 RWX region(s) — possible JIT or injected code." ],
      "regions":   [ { "base", "size", "state", "protect", "type" } ]
  },
  "static": {
      "file_path", "file_name", "is_64bit", "machine", "image_base_preferred",
      "size_of_image", "entry_point_rva", "sections": [...],
      "exports": [ { "name", "ordinal", "rva", "is_forwarder" } ],
      "runtime_formula": "module_base + rva"
  },
  "acquisition": {
      "status", "win32_error", "analyzer_architecture", "target_architecture",
      "native_architecture", "process_handle_opened", "process_query_succeeded",
      "module_enumeration_succeeded", "memory_read_succeeded",
      "enumeration_attempts", "failed_api", "failed_stage", "details",
      "recommended_action"
  },
  "notes":    { ... },
  "warnings": [ ... ]
}
```

The `static` block only appears when the orchestrator ran the disk-based
fallback or when `--static-pe` was used. The `memory_map` block only appears
when the live walk succeeded.

## Layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
