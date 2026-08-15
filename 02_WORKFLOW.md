# Security Jack — Development Workflow

This is the operating procedure for building the project with an AI coding agent (Cursor, Claude Code, Copilot Workspace, etc.). The goal is to prevent the agent from doing what these agents default to: writing a huge amount of code fast, in the wrong order, without tests, that you can't safely review.

## 0. Ground rules for working with the agent

1. **One module at a time.** Never let the agent implement Phase 1 and Phase 2 in the same session, or a whole tier of detectors at once.
2. **Interface and tests before implementation.** For every module: agent proposes the interface → you approve → agent implements → agent writes tests → tests run and pass → only then move on.
3. **You review every diff before it's "done."** Not just "does it compile" — actually read it, especially anything touching `interfaces/` or crossing the `core/` boundary.
4. **If the agent proposes an `#ifdef`, a raw hardware call, or an include from `simulation/` inside `core/`, reject it and point back to §5 of the architecture doc.**
5. **Re-paste the architecture doc (or reference it by path) at the start of every new session.** Agents lose context between sessions; don't assume it remembers the hardware-independence rule from yesterday.

## 1. Task sequence

```
Task 0   Architecture proposal (agent proposes, you approve)         ← no code
Task 1   Core data models + interfaces                               ← code + tests
Task 2   Simulation framework (simulated_ethernet + first scenario)  ← code + tests
Task 3   Phase 1: Device Discovery                                   ← code + tests
Task 4   Phase 1: Network Identity                                   ← code + tests
Task 5   Phase 1: Crypto Identity (simulated auth provider)          ← code + tests
Task 6   Phase 1: Trust Policy + state machine                       ← code + tests
Task 7   Phase 1: end-to-end tests (trusted / unknown / invalid-cred)← tests only
Task 8   Phase 2: Detection engine + SecurityEvent plumbing          ← code + tests
Task 9   Phase 2: Detector — port scan                               ← code + tests
Task 10  Phase 2: Detector — ARP spoof                                ← code + tests
Task 11  Phase 2: Detector — rogue DHCP                                ← code + tests
Task 12  Phase 2: Detector — high packet rate                          ← code + tests
Task 13  Phase 2: Threat engine + scoring                              ← code + tests
Task 14  Phase 2: Response engine (alert/log/quarantine/lockdown)      ← code + tests
Task 15  Phase 2: end-to-end — "trusted device becomes port scanner"   ← tests only
Task 16  Tier 2 detectors (repeat 9-12 pattern per detector)           ← code + tests
Task 17  Tier 3 detectors (repeat pattern)                             ← code + tests
```

Do not start Task N+1 until Task N's tests are green. If you're tempted to skip ahead because "it's just a small detector," that's exactly the moment scope creep happens — hold the line.

## 2. The approval checkpoint, in practice

For every task, use this three-message pattern with the agent:

**Message 1 — Propose:**
> "Propose the interface and data flow for [module]. Do not implement yet. Reference `ARCHITECTURE.md` §[N]."

**Message 2 — Approve or correct:**
> Either "Approved, implement it." or specific corrections.

**Message 3 — Implement + test:**
> "Implement exactly what was approved. Then write unit tests covering [list the specific cases you care about]. Run the tests and show me the output."

This costs a little more back-and-forth per module than "just build it," but it's what keeps a C++ codebase with a hardware boundary from rotting after the first few weeks.

## 3. What "done" means for a module

A module is done when:
- [ ] It compiles as part of the full build (`cmake --build .` from clean).
- [ ] It has unit tests, and they pass.
- [ ] If it's in `core/`, `phase1/`, or `phase2/`: it has zero includes from `simulation/` or `hardware/` (grep for it — don't just trust the agent's word).
- [ ] You've actually read the diff.
- [ ] It's committed with a message naming the task number (e.g. `Task 9: port scan detector`).

## 4. Testing philosophy (do not let the agent skip this)

Three layers, all required, in this order of what to write first:

1. **Unit tests** — one detector, one policy rule, one state transition at a time. Fast, narrow, many of them.
2. **Phase tests** — Phase 1 in isolation ("trusted device → AUTHORIZED", "bad cred → QUARANTINED"), Phase 2 in isolation with a pre-authorized device.
3. **End-to-end scenario tests** — the full 15-step chain from §11 of the architecture doc: connect → identify → authenticate → trust → authorize → normal traffic → attack begins → detected → scored → policy triggers → revoke → quarantine → alert → log.

The end-to-end test is the one that actually proves the architecture works. Don't accept "the port scan detector unit test passes" as evidence the system works — insist on at least one full scenario test per phase before calling it done.

## 5. Session checklist (paste this at the start of each agent session)

```
Before you write any code:
1. Confirm you've read ARCHITECTURE.md.
2. State which Task number (see WORKFLOW.md) we're doing this session.
3. Confirm the module's dependencies are limited to core/ and interfaces/
   (unless this session IS core/ or interfaces/).
4. Propose the interface first. Wait for approval.
```

## 6. When to update the architecture doc itself

The architecture doc is not frozen, but changes to it should be deliberate, not something the agent does mid-implementation-task because it hit friction. If the agent thinks an interface needs to change:
1. Stop implementation.
2. Have it explain why, in a message, referencing the specific architecture section.
3. You decide whether to amend the doc.
4. Only then resume implementation against the updated doc.

## 7. Adding a new attack detector (the repeatable pattern)

Once Tier 1 exists, every subsequent detector follows this exact five-step loop — this is the payoff for the extra rigor early on:

1. Agent proposes: what `PacketEvent` fields it reads, what triggers a `SecurityEvent`, what the event's severity contribution is.
2. You approve or adjust the trigger logic (this is where false-positive risk gets caught).
3. Agent implements `IAttackDetector` for it, registers it with `DetectionEngine`.
4. Agent writes unit tests: at least one true-positive case, one true-negative (normal traffic that must NOT trigger it), and one edge case.
5. Agent adds it to one end-to-end scenario in `simulation/attack_scenarios/`.

## 8. Definition of "ready for hardware"

Before touching `hardware/esp32/`, all of the following must hold:
- Phase 1 and Phase 2 fully pass simulated end-to-end tests.
- `core/` has zero hardware or simulation dependencies (mechanically verified, not assumed).
- Every capability the hardware will need is already expressed as an interface in `interfaces/`.
- You've listed, explicitly, which interfaces the ESP32 port needs to implement (`IEthernetSource`, `IRelay`, possibly `ILogger`) and which it doesn't (`IAuthProvider` may stay server-side).

Only then does `hardware/esp32/` stop being an empty directory.
