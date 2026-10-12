# Contributing to URA

## Read this first

`docs/ETHICS.md` is not optional reading. URA is a read-only
reverse-engineering study tool, and the ethics policy lists what this
project will never accept: memory-write primitives, injection of any
kind, anti-cheat evasion, kernel code, hooks in another process.
PRs in that direction are closed without discussion.

## Building

- Visual Studio 2022, MSVC v143, C++20, Windows 10 SDK.
- `x64` and `x86` configurations supported — use x64 unless you have
  a specific 32-bit target.
- Third-party deps are vendored: drop `nlohmann/json.hpp` into
  `UniversalRuntimeAnalyzer/third_party/nlohmann/` and Dear ImGui
  (plus the win32/dx11 backends) into
  `UniversalRuntimeAnalyzer/third_party/imgui/` if not already there.
- `msbuild UniversalRuntimeAnalyzer.sln /p:Configuration=Release
  /p:Platform=x64`

See `docs/ARCHITECTURE.md` for how the code is organized before you
touch it.

## Adding an engine module

Engine modules live with the other engines (see `GoldSrcEngine` for
the most complete example). A new engine needs:

1. Its signature JSON in `data/signatures/<engine>.json` (patterns
   are data, not code — keep them there).
2. Registration so `--list-engines` picks it up.
3. Graceful fallback when its signature file is missing.

## Rules

- **Read-only, always.** `MemoryReader` exposes no write API and it
  stays that way. Any PR introducing a write path is rejected.
- One change per PR. Small PRs get reviewed fast.
- Commit messages read like a human wrote them: `fix: ...`,
  `feat: ...`.
- Don't commit build output or URA's own JSON reports (`*.json` is
  gitignored except the curated signatures under `data/`).

## Reporting issues

Include: URA version and architecture, Windows version, the target
process, the exact command, and the acquisition diagnostic block
(status, failed stage, win32 error). The diagnostic exists precisely
so issues are debuggable — paste it.
