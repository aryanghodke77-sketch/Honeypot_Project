# Agent Kickoff Prompt

Paste this verbatim as your first message to the AI coding agent in your code editor, with `ARCHITECTURE.md` and `WORKFLOW.md` attached or in the repo root so it can reference them.

---

```
PROJECT: Security Jack — network security device software (C++)

CONTEXT
We are building software for a network security device that will eventually
run on hardware such as an ESP32-based Ethernet device. The hardware is NOT
currently available. The software must be fully executable, testable, and
verifiable right now using a simulator, and designed so that future hardware
integration means writing hardware ADAPTERS behind existing interfaces —
never rewriting core logic.

Read ARCHITECTURE.md and WORKFLOW.md in this repo before doing anything else.
Treat them as binding. If anything below conflicts with them, ARCHITECTURE.md
wins.

TWO PHASES

Phase 1 — Device Verification
Objective: given a connected device, decide whether it is TRUSTED or
NON_TRUSTED and authorize or quarantine it accordingly. This is an identity
and authorization question — NOT "is this device malicious." Covers: device
discovery, network identity (MAC/IP/hostname/vendor/DHCP), cryptographic
identity (simulated cert/credential validation now, real auth server later,
behind IAuthProvider), device posture (interface-only for now — do not
invent capabilities Ethernet-only access can't actually provide), a
deterministic trust policy (rules, not a numeric score), and the device
state machine.

Phase 2 — Trusted-Device Defence
Objective: given a device that has ALREADY passed Phase 1 and is AUTHORIZED,
continuously monitor it and detect if it starts behaving maliciously. Covers:
continuous monitoring, attack detectors (start with port scan, ARP spoof,
rogue DHCP, high packet rate — do not build more than one detector at a
time), a threat engine that scores SecurityEvents per device, and a response
engine (log / alert / quarantine / lockdown) that can revoke trust.

HARDWARE INDEPENDENCE — NON-NEGOTIABLE
- core/, phase1/, and phase2/ may depend ONLY on interfaces/ and core/
  itself. Never on simulation/ or hardware/.
- All hardware-shaped capabilities (reading packets, controlling a relay,
  authenticating a device, logging) go through an abstract interface in
  interfaces/. Concrete implementations live in simulation/ (now) and
  hardware/esp32/ (later, empty for now).
- Never write #ifdef ESP32 or similar inside core/, phase1/, or phase2/.
- Never construct a concrete simulator or hardware object inside core logic
  — dependency-inject interfaces from the top level only.
- If a capability requires hardware or infrastructure that doesn't exist
  yet, represent it as an interface + a clearly commented boundary, not a
  fake/hardcoded implementation.

DATA MODELS (define these first, in core/, before any logic)
DeviceProfile, PacketEvent, SecurityEvent, AuthenticationResult,
TrustDecision, ThreatAssessment, DeviceState. See ARCHITECTURE.md §4 for
exact fields — use those, don't invent your own shapes.

TESTING — REQUIRED FOR EVERY MODULE
Unit tests for the module itself, plus phase-level tests, plus at minimum
one full end-to-end scenario test per phase before that phase is considered
done (see ARCHITECTURE.md §11/§12 and WORKFLOW.md §4 for what "full
end-to-end" means — it's the entire chain from connect through
authorize/quarantine, not just a detector firing in isolation).

DEVELOPMENT RULE — DO NOT IMPLEMENT EVERYTHING AT ONCE
Follow the task sequence in WORKFLOW.md exactly, one task at a time. For
each task:
  1. Propose the interface/design. Do not write implementation code yet.
  2. Wait for my explicit approval.
  3. Implement exactly what was approved.
  4. Write tests.
  5. Run the tests and show me the output.
  6. Stop and wait for the next task.

YOUR FIRST RESPONSE, RIGHT NOW
Do not write any implementation code. Instead:
1. Confirm you've read ARCHITECTURE.md and WORKFLOW.md.
2. Propose the repository skeleton (directories + CMakeLists.txt stubs)
   matching ARCHITECTURE.md §3 and §11.
3. Propose the exact C++ definitions for the core data models in
   ARCHITECTURE.md §4 — types, headers, nothing else yet.
4. Propose the four interfaces in ARCHITECTURE.md §5 — signatures only.
5. Stop and wait for my review before creating any files.
```

---

## Notes on using this prompt

- If your agent/editor supports attaching files directly (Claude Code, Cursor with `@file`), reference `ARCHITECTURE.md` and `WORKFLOW.md` by path instead of pasting their content inline — keeps the prompt shorter and the docs stay the single source of truth.
- If the agent ignores step 5 and starts generating implementation files anyway, stop it and re-paste just the "YOUR FIRST RESPONSE, RIGHT NOW" section. This is the single most common failure mode with these prompts — agents default to maximal helpfulness, which here means doing too much.
- Keep this file in your repo (e.g. `docs/03_AGENT_KICKOFF_PROMPT.md`) and reuse the "propose → approve → implement → test" pattern from it for every subsequent task, not just the first one.
