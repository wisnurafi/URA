# Universal Runtime Analyzer (URA)

A modular, **read-only** runtime memory analysis framework for Windows games and
native applications, written in C++20. Built as an academic reverse-engineering
project to study process memory layout, PE structures, pattern scanning, MSVC
RTTI, vtable inference, cross-references, and engine-specific runtime
introspection.

## Capabilities

- **Process attachment** with a read-only handle (`PROCESS_QUERY_INFORMATION |
  PROCESS_VM_READ` only). Falls back to `PROCESS_QUERY_LIMITED_INFORMATION`
  when full QUERY is denied.
- **Module enumeration** with `EnumProcessModulesEx`, plus a `EnumProcessModules`
  fallback for protected targets.
- **PE parser** for both PE32 and PE32+ images. Reads sections, characteristics,
  Export Address Table (with name+ordinal+RVA), forwarder detection, and image
  metadata.
- **Pattern scanner** using IDA-style byte signatures (`"48 8B 05 ?? ?? ?? ??"`)
  with optional address transforms (RIP-relative-32, absolute-32, absolute-64).
- **Signature loader** — load patterns from `data/signatures/<engine>.json`
  files at runtime; engines fall back to inline patterns when the file is
  absent.
- **String scanner** for ASCII and UTF-16LE markers across `.rdata`/`.data`.
- **Cross-reference scanner** — mini decoder for `CALL/JMP near (E8/E9)`,
  `LEA/MOV r64, [RIP+disp32]`, indirect `CALL/JMP [imm32]`, and absolute
  `MOV reg, imm32` / `PUSH imm32` on x86. Given a target address, returns
  every instruction in `.text` that references it.
- **MSVC RTTI / vtable scanner** — walks `.rdata` for
  `RTTICompleteObjectLocator` candidates, dereferences `TypeDescriptor`,
  recovers mangled names (`.?AVCBaseEntity@@`), best-effort demangles them
  (`class CBaseEntity`), and counts plausible vtable slots.
- **Memory region map** via `VirtualQueryEx` — every committed/reserved
  region with state, protection, and type. Flags RWX and executable
  `MEM_PRIVATE` regions as anomalies (classic JIT / injection signals).
- **JSON exporter** with versioned schema (`schema_version: "1"`) covering
  process, modules, groups, classes, memory map, notes, and warnings.
- **Two frontends** — a CLI (`URA.exe ...`) and an optional Dear ImGui +
  DirectX 11 GUI (`URA.exe --gui`).

## Scope (read-only by design)

URA explicitly **does not**:

- Write to remote process memory.
- Inject DLLs or hijack threads.
- Bypass, evade, or interact with anti-cheat systems.
- Patch, hook, or modify game logic.
- Touch kernel mode.

`MemoryReader` exposes no write API. The Win32 process handle is opened with
read-only flags. See [`docs/ETHICS.md`](docs/ETHICS.md) for the full policy.

## Supported Targets

| Target              | Engine module          | Status                              |
| ------------------- | ---------------------- | ----------------------------------- |
| Counter-Strike 1.6  | `GoldSrcEngine`        | Verified end-to-end                 |
| Generic native exe  | `GenericNativeEngine`  | Verified                            |
| Goose Goose Duck    | `UnityIL2CPPEngine`    | EAC blocks read; ethical refusal    |
| Among Us            | `UnityIL2CPPEngine`    | Skeleton                            |
| Source engine games | `SourceEngine`         | Skeleton                            |

## Build

- Visual Studio 2022, MSVC v143, C++20.
- Both `x64` and `x86` configurations supported (CS 1.6 is 32-bit; Unity
  IL2CPP titles are 64-bit).
- Drop [`nlohmann/json.hpp`](https://github.com/nlohmann/json/releases) into
  `UniversalRuntimeAnalyzer/third_party/nlohmann/json.hpp`.
- Drop [Dear ImGui](https://github.com/ocornut/imgui) into
  `UniversalRuntimeAnalyzer/third_party/imgui/` (top-level files plus
  `backends/imgui_impl_win32.{h,cpp}` and `backends/imgui_impl_dx11.{h,cpp}`).
- Open `UniversalRuntimeAnalyzer.sln` and build.

## Quick start

CLI:

```text
URA.exe --list-engines
URA.exe --list-processes
URA.exe --pid 1234 --auto                              # auto-detect engine
URA.exe --pid 1234 --engine generic_native --out r.json
URA.exe --process hl.exe --engine goldsrc --out cs16.json --verbose
```

GUI:

```text
URA.exe --gui
```

The GUI presents a process list, engine selector, and tabbed views for
modules, groups (resolved offsets), the address-space memory map, recovered
RTTI classes, notes, and the raw JSON export.

## Output schema (v1, abridged)

```json
{
  "tool":     { "name", "version", "schema_version", "generated_at" },
  "engine":   { "id", "display_name", "duration_ms" },
  "process":  { "pid", "name", "path", "is_wow64", "bitness" },
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
  "notes":    { "<engine>.<key>": "<value>" },
  "warnings": [ ... ]
}
```

## Layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
