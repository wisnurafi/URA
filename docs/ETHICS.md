# Ethics & Scope Policy

URA is an academic reverse-engineering framework. Use is restricted to:

- Programs you own or have explicit permission to analyze.
- Single-player / offline contexts.
- Educational study of runtime memory layout, PE format, and game engines.

## Hard restrictions (enforced by design)

The codebase deliberately does not implement and will not accept contributions
for:

- `WriteProcessMemory`, `VirtualProtectEx`, or any memory-write primitive
  against another process.
- `CreateRemoteThread`, manual DLL injection, APC injection, thread hijacking.
- Anti-cheat detection, evasion, or signature spoofing.
- Kernel drivers or any ring-0 code.
- Hooks (IAT, EAT, inline, vectored) installed in another process.
- Network code that interacts with multiplayer servers.

The Win32 process handle is opened with
`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` only. The `MemoryReader` API
exposes no write path.

## Responsible use

- Do not run URA against online multiplayer sessions, even read-only:
  some anti-cheats flag any foreign handle to the game process.
- Do not redistribute extracted offsets in a context that facilitates cheating.
- When publishing findings, prefer abstract structural descriptions over
  copy-paste-ready offsets for live games.

If you are a course reviewer evaluating this project, the scope above is the
intended deliverable. Anything outside of it is out of scope.
