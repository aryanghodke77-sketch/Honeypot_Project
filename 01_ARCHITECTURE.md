# Security Jack — Architecture

## 1. Core idea

Two phases, one core, hardware deferred.

```
                    PHASE 1                      PHASE 2
              DEVICE VERIFICATION          TRUSTED-DEVICE DEFENCE
              "Who are you?"               "What are you doing now?"
                     │                              │
                     └──────────────┬───────────────┘
                                     ▼
                            COMMON CORE (C++)
                                     │
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
              Data Models      Interfaces         Logging
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                                ▼
              NOW: Simulator                   LATER: ESP32 adapter
```

Phase 1 decides whether a device is **trusted**. Phase 2 assumes trust can go bad and continuously re-checks it. Neither phase, nor the core between them, is allowed to know whether its input came from a simulator or real Ethernet hardware — that's the one rule everything else in this document protects.

## 2. Three concepts, never mixed

| Concept | Question | Owned by |
|---|---|---|
| **Identity** | Who is this device? | `core/identity/` |
| **Trust** | Should it have access *right now*? | `core/policy/` |
| **Threat** | Is it behaving maliciously *right now*? | `core/threat/` |

Identity is established once (Phase 1) and rarely changes. Trust is a current, revocable decision. Threat is continuously recomputed (Phase 2) and can revoke trust. Do not let detection code touch identity fields, and do not let identity code make authorization decisions — that's the policy engine's job alone.

## 3. Repository layout

```
security-jack/
├── core/
│   ├── types/             PacketEvent, DeviceProfile, AuthenticationResult, TrustDecision, ThreatAssessment, DeviceState, SecurityEvent, EventType
│   ├── identity/         NetworkIdentity, CryptoIdentity, PostureIdentity
│   ├── policy/            TrustPolicy, Authorization
│   ├── threat/            ThreatEngine, ThreatScore
│   └── state/             DeviceStateMachine
│
├── phase1/
│   ├── verification_workflow.{h,cpp}
│   └── tests/
│
├── phase2/
│   ├── attack_detectors/
│   │   ├── port_scan.{h,cpp}
│   │   ├── arp_spoof.{h,cpp}
│   │   ├── rogue_dhcp.{h,cpp}
│   │   ├── packet_rate.{h,cpp}
│   │   ├── http_anomaly.{h,cpp}
│   │   └── smb_probe.{h,cpp}
│   ├── response_engine.{h,cpp}
│   └── tests/
│
├── simulation/
│   ├── simulated_ethernet.{h,cpp}
│   ├── simulated_devices/
│   ├── normal_traffic/
│   └── attack_scenarios/
│
├── interfaces/          <-- the hardware-independence boundary (see §5)
│   ├── i_ethernet_source.h
│   ├── i_relay.h
│   ├── i_auth_provider.h
│   └── i_logger.h
│
├── hardware/
│   └── esp32/            EMPTY for now, on purpose
│
├── tests/
│   ├── unit/
│   ├── phase1/
│   ├── phase2/
│   └── end_to_end/
│
├── third_party/
└── CMakeLists.txt
```

## 4. Core data models

Define these first in `core/types/`, before any logic. Everything else is built on top.

```cpp
// core/types/protocol.h
enum class Protocol { TCP, UDP, ARP, DHCP, ICMP, UNKNOWN };

// core/types/device_profile.h
struct DeviceProfile {
    std::string device_id;   // stable internal id, not the MAC
    std::string mac;
    std::string ip;
    std::string hostname;
    std::string vendor;       // from OUI lookup
    std::optional<std::string> dhcp_option55; // parameter request list, etc.
    std::chrono::system_clock::time_point first_seen;
};

// core/types/packet_event.h
struct PacketEvent {
    std::string src_mac, dst_mac, src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;
    Protocol protocol = Protocol::UNKNOWN;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> payload;    // may be empty; detectors decide if they need it
};

// core/types/authentication_result.h
struct AuthenticationResult {
    bool success;
    std::string method;              // "network_identity" | "certificate" | ...
    std::optional<std::string> failure_reason;
};

// core/types/trust_decision.h
enum class TrustLevel { UNKNOWN, NON_TRUSTED, TRUSTED };
struct TrustDecision {
    TrustLevel level;
    std::string reason;
    std::chrono::system_clock::time_point decided_at;
};

// core/types/threat_assessment.h
enum class ThreatLevel { NORMAL, LOW, MEDIUM, HIGH, CRITICAL };
struct ThreatAssessment {
    ThreatLevel level;
    int score;                       // 0-100, detectors contribute deltas
    std::vector<std::string> contributing_events; // SecurityEvent ids
};

// core/types/device_state.h
enum class DeviceState {
    DISCONNECTED, UNKNOWN, VERIFYING,
    TRUSTED, NON_TRUSTED,
    AUTHORIZED, QUARANTINED, LOCKDOWN
};

// core/types/security_event.h
enum class EventType {
    PORT_SCAN_DETECTED,
    ARP_SPOOF_DETECTED,
    ROGUE_DHCP_DETECTED,
    HIGH_PACKET_RATE_DETECTED
    // Tier 2/3 events added incrementally
};

struct SecurityEvent {
    std::string id;              // unique identifier
    std::string device_id;       // which device generated this event
    EventType type;              // what kind of attack
    std::string description;     // human-readable description
    std::chrono::system_clock::time_point timestamp;
};
```

Rules for these types:
- Dependency-neutral data only. Must compile with zero includes from `simulation/`, `hardware/`, or `interfaces/`.
- Plain data + invariants only. No I/O, no knowledge of sockets or ESP32.
- Every field that could plausibly come from real hardware later must already exist here in Phase 1, even if the simulator is the only thing populating it.

## 5. The hardware-independence boundary

This is the part that determines whether your ESP32 port later is a few hundred lines or a rewrite. C++ makes this easy to get wrong (raw pointers to peripherals leaking into logic) so be explicit about it.

**The types layer:** `core/types/` is the ONLY data model layer that `interfaces/` may reference. All interfaces use types from `core/types/` to avoid circular dependencies.

**Dependency rules:**
- `interfaces/` may only include headers from `core/types/`.
- Individual components in `core/`, `phase1/`, and `phase2/` may depend on `interfaces/` only when required by dependency injection. Not all components need this dependency.
- They must never `#include` anything from `simulation/` or `hardware/`.

```cpp
// interfaces/i_ethernet_source.h
class IEthernetSource {
public:
    virtual ~IEthernetSource() = default;
    virtual std::optional<PacketEvent> poll() = 0;   // non-blocking, returns nullopt if idle
    virtual void start() = 0;
    virtual void stop() = 0;
};

// interfaces/i_relay.h
class IRelay {
public:
    virtual ~IRelay() = default;
    virtual void allow(const std::string& device_id) = 0;
    virtual void block(const std::string& device_id) = 0;
};

// interfaces/i_auth_provider.h
class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;
    virtual AuthenticationResult verify(const DeviceProfile&) = 0;
};

// interfaces/i_logger.h
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(LogLevel, const std::string& msg) = 0;
};
```
- `simulation/simulated_ethernet.cpp` implements `IEthernetSource`.
- `hardware/esp32/esp32_ethernet_source.cpp` will implement the same interface, later, without touching `core/` at all.
- The engines (`DetectionEngine`, `TrustPolicy`, etc.) take an `IEthernetSource&` / `IRelay&` in their constructor (dependency injection). They never construct a concrete simulator or hardware object themselves — that happens once, at the top level (`main.cpp` or the test harness), which is the only place allowed to know which implementation is in use.

If you ever find yourself writing `#ifdef ESP32` inside `core/`, `phase1/`, or `phase2/`, that's a violation of this boundary — stop and move that branch up into the adapter instead.

### Interface implementation mapping

| Interface | Simulator implementation | ESP32 implementation (future) |
|-----------|-------------------------|--------------------------------|
| `IEthernetSource` | `SimulatedEthernet` - replays `PacketEvent` sequences from scenarios | `ESP32EthernetSource` - reads actual Ethernet frames |
| `IRelay` | `SimulatedRelay` - logs allow/block actions | Real switch/traffic controller hardware |
| `IAuthProvider` | `SimulatedAuthProvider` - checks credentials in memory | External authentication server (RADIUS, cert authority) |
| `ILogger` | `ConsoleLogger` - prints to stdout | Structured logging to flash/SD card |

## 6. Phase 1 — Device Verification

**Objective:** given device discovery information and identity/authentication results, produce an initial `TrustDecision` (TRUSTED → AUTHORIZED, or NON_TRUSTED → QUARANTINED).

```
DEVICE CONNECTED
      │
      ▼
Device Discovery ──► DeviceProfile
      │
      ▼
Identity Evaluation
   ├─ NetworkIdentity   (MAC, IP, hostname, vendor, DHCP)
   ├─ CryptoIdentity    (cert/credential — via IAuthProvider)
   └─ PostureIdentity   (optional, architecture-only for now)
      │
      ▼
TrustPolicy.evaluate(identity results) ──► TrustDecision
      │
      ├─ TRUSTED ─────► DeviceState::AUTHORIZED
      └─ NON_TRUSTED ─► DeviceState::QUARANTINED
```

`TrustPolicy` in Phase 1 is **deterministic rules**, not a numeric score:

```cpp
TrustDecision TrustPolicy::evaluate(const NetworkIdentityResult& net,
                                     const AuthenticationResult& auth) {
    if (!net.mac_known) return {TrustLevel::NON_TRUSTED, "unknown MAC", now()};
    if (!auth.success)  return {TrustLevel::NON_TRUSTED, auth.failure_reason.value_or("auth failed"), now()};
    return {TrustLevel::TRUSTED, "network identity + credential verified", now()};
}
```

Do not add a numeric trust score in Phase 1. That's premature — save scoring for Phase 2's threat engine, which has a genuinely different job (aggregating many weak signals over time, not making a single point-in-time decision).

## 7. Phase 2 — Trusted-Device Defence

**Objective:** given a stream of `PacketEvent`s from an already-`AUTHORIZED` device, detect malicious behavior and revoke trust if warranted.

```
AUTHORIZED DEVICE
      │
      ▼
Continuous Monitor (ARP / DHCP / Traffic)
      │
      ▼
Attack Detectors ──► SecurityEvent(s)
      │
      ▼
ThreatEngine.score(events) ──► ThreatAssessment
      │
      ├─ NORMAL/LOW    ─► keep AUTHORIZED (log only)
      ├─ MEDIUM         ─► ALERT
      ├─ HIGH            ─► QUARANTINE (revoke trust)
      └─ CRITICAL       ─► LOCKDOWN
```

Each attack detector is independent and stateless-in, stateful-out:

```cpp
class IAttackDetector {
public:
    virtual ~IAttackDetector() = default;
    virtual std::optional<SecurityEvent> onPacket(const PacketEvent&) = 0;
    virtual std::string name() const = 0;
};
```

`DetectionEngine` owns a `vector<unique_ptr<IAttackDetector>>` and fans every `PacketEvent` out to all of them. Adding detector #7 never means touching detector #1–6 or the engine's control flow — only registering the new one. This is the extension point for the Tier 2/3 detectors later.

`ThreatEngine` consumes `SecurityEvent`s (not raw packets) and maintains a per-device score. Keep the scoring function simple and inspectable to start — a table of event-type → point delta, decayed over time — not a black box.

## 8. Detector build order

Build and fully test each tier before starting the next. Do not parallelize this — a working port-scan detector with full tests teaches you the pattern for the other eleven.

**Tier 1** (build first): port scanning, ARP spoofing, rogue DHCP, high packet rate.
**Tier 2**: suspicious HTTP, SMB probing, DNS anomalies, protocol anomalies.
**Tier 3**: C2-like beaconing, reconnaissance patterns, MAC/IP spoofing, LLMNR/NBNS poisoning.

## 9. Simulation layer

The simulator is your hardware for now. Treat it as a first-class, permanent part of the system (it stays useful for regression testing even after real hardware exists), not a throwaway stub.

```
simulation/
├── simulated_devices/
│   ├── trusted_device
│   ├── unknown_device
│   └── compromised_trusted_device   <-- starts clean, turns malicious mid-scenario
├── normal_traffic/
│   ├── normal_dhcp
│   ├── normal_arp
│   └── normal_http
└── attack_scenarios/
    ├── port_scan
    ├── arp_spoof
    ├── rogue_dhcp
    └── ...
```

`simulated_ethernet.cpp` implements `IEthernetSource::poll()` by replaying a scenario's `PacketEvent` sequence deterministically (same input every run — no `rand()` without a fixed seed). This determinism is what makes Phase 1→Phase 2 end-to-end tests reliable.

## 10. State machine

```
DISCONNECTED → UNKNOWN → VERIFYING ─┬─► TRUSTED → AUTHORIZED ─┬─► (stays, Phase 2 monitors)
                                     └─► NON_TRUSTED → QUARANTINED
                                                                └─► (Phase 2 detects attack) → QUARANTINED → LOCKDOWN
```

One `DeviceStateMachine` per device, owned by `DeviceManager`. Phase 1 drives the left half of this diagram; Phase 2 drives the transition out of `AUTHORIZED` back into `QUARANTINED`/`LOCKDOWN`. No other code should mutate `DeviceState` directly — always go through the state machine so transitions stay valid and logged.

## 11. Build structure (CMake)

```cmake
# top-level CMakeLists.txt
add_subdirectory(core/types)  # MUST have zero dependencies
add_subdirectory(core)        # may depend on core/types and interfaces
add_subdirectory(interfaces)  # may depend on core/types only
add_subdirectory(simulation)
add_subdirectory(phase1)
add_subdirectory(phase2)
add_subdirectory(tests)

# hardware/esp32 is NOT added here yet — it gets its own
# ESP-IDF / PlatformIO build later, linking against core/ as a static lib.

add_executable(security_jack_sim main_sim.cpp)
target_link_libraries(security_jack_sim PRIVATE core phase1 phase2 simulation)
```

**Verification requirements:**
- `core/types` must compile with zero includes from `simulation/`, `hardware/`, or `interfaces/`
- `core/` must compile with zero dependency on `simulation` or any hardware SDK
- `interfaces/` must only include headers from `core/types/`

## 12. What NOT to do

- Don't give Phase 1 a job it doesn't have ("is this device malicious?" — that's Phase 2).
- Don't build a numeric trust score in Phase 1.
- Don't build more than one detector at a time.
- Don't let `core/` include anything from `simulation/` or `hardware/`.
- Don't invent hardware capabilities (e.g., pretending you can read OS posture over bare Ethernet) — represent the gap with an interface and a comment marking the boundary, not a fake implementation.
- Don't use `#ifdef ESP32` (or similar) inside `core/`, `phase1/`, `phase2/`.
