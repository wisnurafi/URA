# Architecture

## Layering

```
+-----------------------------------------------------+
|  app/        CliApp + GuiApp (Dear ImGui frontend)  |
+-----------------------------------------------------+
|  engine/     IGameEngine + concrete engine modules  |
+-----------------------------------------------------+
|  analysis/   Signatures, pattern + string scanning, |
|              SignatureLoader, XrefScanner,          |
|              RttiScanner                            |
+-----------------------------------------------------+
|  platform/   WinAPI: process, modules, memory,      |
|              PE, address space (VirtualQueryEx)     |
+-----------------------------------------------------+
|  core/       Types, Result<T>, Logger, utils        |
+-----------------------------------------------------+
```

Strict downward dependency: a layer may only `#include` from layers below it.
This keeps engine modules portable across analysis backends and isolates
WinAPI usage to `platform/`.

## Key abstractions

### `core::Result<T>`
Lightweight `expected`-like sum type. Every fallible operation returns
`Result<T>`; no exceptions cross module boundaries.

### `platform::ProcessHandle`
RAII wrapper around a Win32 `HANDLE` opened with the **minimum** rights
required for analysis: `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
Falls back to `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` when
the full QUERY mask is denied. Never `PROCESS_VM_WRITE` or
`PROCESS_VM_OPERATION`.

### `platform::MemoryReader`
Thin wrapper over `ReadProcessMemory`. Provides typed reads, bulk reads,
best-effort range reads (tolerates unreadable pages mid-region), and safe
pointer chains. **No write API exists, by design.**

### `platform::MemoryMapWalker`
Walks the target's user-mode VAD via `VirtualQueryEx`, capturing each
region's state / protection / type and pre-decoding the raw flags into
human-readable strings (`PAGE_EXECUTE_READ`, `MEM_IMAGE`, etc.). Surfaces
anomaly heuristics (RWX, executable `MEM_PRIVATE`).

### `platform::PEParser`
Re-parses headers and the section table directly from remote memory.
Reads the Export Address Table (`AddressOfNames` / `AddressOfNameOrdinals`
/ `AddressOfFunctions`) and recovers `(name, ordinal, RVA)` triples,
including forwarder detection.

### `analysis::PatternScanner`
IDA-style byte signatures (`"48 8B 05 ?? ?? ?? ??"`) with mask. Optional
post-processing transforms map a hit to a derived address: RIP-relative
disp32 (x64 LEA/MOV/CALL targets), absolute imm32 (x86), absolute imm64.

### `analysis::SignatureLoader`
Loads `Signature` lists from `data/signatures/<engine>.json`. Engines try
to load their file at startup and silently fall back to inline patterns
on failure — patterns are data, not code.

### `analysis::XrefScanner`
Mini decoder for the small set of x86/x64 instruction encodings that
produce code references: `E8/E9 disp32` (CALL/JMP near), `FF 15 / FF 25`
(indirect CALL/JMP), `48 8D <ModRM> disp32` (LEA `[rip+disp32]`),
`48 8B <ModRM> disp32` (MOV from RIP-relative), and `B8..BF imm32`,
`68 imm32` on x86 for absolute address loads. Linear walk over `.text`,
returns every instruction whose computed target equals the queried
address.

### `analysis::RttiScanner`
Discovers MSVC C++ RTTI metadata. Scans `.rdata` for pointer slots that
could be `RTTICompleteObjectLocator` (RCOL) entries; validates by reading
the RCOL header, dereferencing the `TypeDescriptor`, and recovering the
mangled name. The pointer slot's location is `vftable[-1]`, so the vtable
proper begins one pointer later. Counts plausible vtable slots by
following pointers until one falls outside `.text` or is null. Includes
a best-effort `.?AVName@@`-shape demangler for class/struct names.

### `engine::IGameEngine`
The plugin contract:

```cpp
struct IGameEngine {
    virtual ~IGameEngine() = default;
    virtual std::string id() const = 0;            // "unity_il2cpp"
    virtual std::string display_name() const = 0;  // "Unity (IL2CPP)"
    virtual bool detect(const EngineContext&) const = 0;
    virtual Result<AnalysisReport> analyze(EngineContext&) const = 0;
};
```

`detect()` is a fast, side-effect-free probe (e.g. "is `GameAssembly.dll`
loaded?"). `analyze()` performs the full scan and produces a structured
`AnalysisReport`.

### `engine::EngineRegistry`
Holds all registered engines. Auto-detect picks the first `detect()` hit;
explicit `--engine` skips detection.

### `engine::AnalysisReport`
A tree of named offsets, RVAs, signature matches, RTTI findings, address
space snapshot, and metadata. Engine-agnostic shape, serialized by
`export/JsonExporter`.

### `app::CliApp` / `app::GuiApp`
Two parallel frontends sharing the same orchestrator logic:
1. Resolve PID (by `--pid` or `--process`).
2. Open read-only handle.
3. Enumerate modules.
4. Walk the memory map.
5. Pick engine (auto-detect or `--engine`).
6. Run engine `analyze()`.
7. Emit JSON / render tabs.

## Data flow

```
CliApp / GuiApp
  └─ ProcessEnumerator ──> pid
        └─ ProcessHandle (read-only)
              └─ ModuleEnumerator ──> modules + PE headers
              └─ MemoryMapWalker ──> region inventory
                    └─ EngineContext
                          ├─ EngineRegistry::auto_detect()
                          └─ IGameEngine::analyze()
                                └─ analysis::{Pattern,String,Xref,Rtti}Scanner
                                      └─ AnalysisReport
                                            └─ JsonExporter ──> *.json
```

## Adding a new engine

1. Create `src/engine/modules/<engine>/<Name>Engine.{hpp,cpp}`.
2. Implement `IGameEngine`.
3. Register it in `EngineRegistry::register_builtin()`.
4. Optionally ship a `data/signatures/<engine>.json`.

The framework knows nothing about your engine specifics; everything else
(scanning, PE parsing, RTTI walking, memory map, JSON export) is reused.
