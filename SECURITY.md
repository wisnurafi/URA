# Security Policy

## Reporting a vulnerability

Open a **private security advisory** on GitHub. Don't open a public
issue for security reports.

What helps: the URA version, Windows version and architecture (x64 /
x86), the target you were analyzing, and steps to reproduce.

## What counts

URA is a read-only analysis tool — its whole design is "observe,
don't touch". The security-relevant surface is small but real:

- Anything that breaks the read-only guarantee: a write path to
  another process smuggled in through the reader, the exporter, or a
  new engine module.
- Unsafe parsing of untrusted input: malformed PE files via
  `--static-pe`, crafted JSON signatures in `data/signatures/`.
- Handle or privilege mishandling around process attachment.

Not security issues:

- Requests for write primitives, injection, anti-cheat evasion, or
  kernel code. Read `docs/ETHICS.md` — those are rejected by design,
  not missing features. Don't file them as vulnerabilities.
- Anti-cheat software flagging URA's read handle. That's the
  anti-cheat doing its job (see the Goose Goose Duck row in the
  README).

## Scope

In scope: this repo's own code — the reader, scanners, engines, CLI/GUI.

Out of scope: third-party libraries (`third_party/`), the Windows
API itself, the targets being analyzed.

## What to expect

Indie project, no bug bounty, no SLA. I'll acknowledge your report,
fix confirmed issues, and credit you unless you'd rather stay
anonymous.
