# Security Jack — Localized Honeypot System

C++17 network security software for a localized honeypot: verify which devices
are trusted (Phase 1), then detect and respond when a trusted device turns
malicious (Phase 2). The core is hardware-independent — it runs on a simulator
now, and future hardware (ESP32) plugs in via the interfaces in `interfaces/`.

## Status

Full end-to-end chain working on the simulator:
connect → identify → authenticate (HMAC-SHA256 challenge-response) → authorize
→ detect attack → score threat → alert/quarantine/lockdown. Remaining work:
more detectors, ESP32 port.

## Docs

- `01_ARCHITECTURE.md` — architecture and design rules

## Setup & build

Requires a C++17 compiler. This machine uses WinLibs MinGW-w64 GCC 16.1.0 at
`C:\mingw64`. Use full paths — bare `g++` resolves to an old GCC 6.3.0 that
cannot compile the code.

Full-chain demo:

```
C:\mingw64\bin\g++.exe -std=c++17 -I. main_sim.cpp simulation\*.cpp core\identity\enrollment_registry.cpp core\policy\trust_policy.cpp core\state\device_state_machine.cpp core\threat\threat_engine.cpp phase1\verification_workflow.cpp phase2\*.cpp -o main_sim.exe
main_sim.exe
```

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