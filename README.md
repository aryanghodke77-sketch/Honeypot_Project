# Security Jack — Localized Honeypot System

C++17 network security software for a localized honeypot: verify which devices
are trusted (Phase 1), then detect and respond when a trusted device turns
malicious (Phase 2). The core is hardware-independent — it runs on a simulator
now, and future hardware (ESP32) plugs in via the interfaces in `interfaces/`.

## Status

Task 1 (data models + interfaces + tests) complete. Next: Task 2 — simulation
framework.

## Docs

- `01_ARCHITECTURE.md` — architecture and design rules

## Setup & build

Requires a C++17 compiler. This machine uses WinLibs MinGW-w64 GCC 16.1.0 at
`C:\mingw64`. Use full paths — bare `g++` resolves to an old GCC 6.3.0 that
cannot compile the code.

Unit tests (12 checks):

```
C:\mingw64\bin\g++.exe -std=c++17 -I. tests\unit\task1_validation.cpp -o tests\unit\task1_validation.exe
tests\unit\task1_validation.exe
```

Interactive verifier:

```
C:\mingw64\bin\g++.exe -std=c++17 -I. tests\interactive\task1_interactive.cpp -o tests\interactive\task1_interactive.exe
tests\interactive\task1_interactive.exe
```

In VSCode, `Ctrl+Shift+B` builds the active file via `.vscode/tasks.json`.