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
| **Identification** | Which device are we talking about? | Device discovery (observed) |
| **Authentication** | Can this device prove possession of the enrolled credential? | `core/identity/` |
| **Trust** | Should it have access *right now*? | `core/policy/` |
| **Threat** | Is it behaving maliciously *right now*? | `core/threat/` |

Identification is purely observational (MAC, IP, hostname). Authentication verifies cryptographic proof of identity. Trust is a policy decision. Threat is continuously recomputed (Phase 2) and can revoke trust.

## 3. Repository layout

```
security-jack/
├── core/
│   ├── types/             PacketEvent, DeviceProfile, DeviceIdentity, AuthenticationResult, TrustDecision, ThreatAssessment, DeviceState, SecurityEvent, EventType
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
// OBSERVED/network identification data only - NOT a stable identity
struct DeviceProfile {
    std::string mac;                 // observed MAC address (identifier, not proof)
    std::string ip;                  // current IP address
    std::string hostname;              // may be spoofed
    std::string vendor;               // from OUI lookup (can be faked)
    std::optional<std::string> dhcp_option55; // parameter request list, etc.
    std::chrono::system_clock::time_point first_seen;
};

// core/types/device_identity.h
// The ENROLLED cryptographic identity, established during provisioning
struct DeviceIdentity {
    std::string device_id;   // stable internal id assigned during enrollment
    std::string mac;          // associated MAC (used for identification, not auth)
    std::string public_key_jwk;  // public key in JWK format
    std::optional<std::string> certificate_serial;
    std::chrono::system_clock::time_point enrolled_at;
    bool allowlisted;         // legacy MAC allowlist (weaker mechanism)
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
// Result of an authentication attempt
struct AuthenticationResult {
    bool success;
    std::string mechanism;           // "certificate" | "mac_allowlist" | "manual"
    std::optional<std::string> signature;  // for challenge-response proofs
    std::optional<std::string> failure_reason;
};

// core/types/trust_decision.h
// Policy decision about whether an authenticated device should be authorized
enum class TrustLevel { UNKNOWN, NON_TRUSTED, TRUSTED };
struct TrustDecision {
    TrustLevel level;
    std::string reason;              // explains why: "cert verified + policy approved" etc.
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
// Device lifecycle states
enum class DeviceState {
    DISCONNECTED,           // no recent network presence
    IDENTIFIED,             // seen on network, has DeviceProfile, may have DeviceIdentity
    AUTHENTICATING,         // authentication attempt in progress
    AUTHENTICATED,          // crypto identity verified (needs policy approval)
    TRUSTED, NON_TRUSTED,   // intermediate states
    AUTHORIZED,             // fully trusted and allowed network access
    QUARANTINED,            // restricted/isolated (failed auth or threat detected)
    REVOKED,                // identity permanently no longer trusted
    LOCKDOWN                // severe threat, complete isolation
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
    // Authenticate a device: takes observed profile and enrolled identity
    // Returns authentication result; does NOT perform registry lookup
    virtual AuthenticationResult authenticate(
        const DeviceProfile& observed,
        const DeviceIdentity& enrolled
    ) = 0;
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

## 6. Enrollment and Authentication Lifecycle

Device enrollment establishes the trusted identity:

```
Device Enrollment / Provisioning
         ↓
Generate/provision key pair on device or administratively
         ↓
Protect private key on device (hardware keystore, TPM, secure element, or pre-provisioned)
         ↓
Issue/register certificate or public key with Identity Server
         ↓
Identity Server stores: DeviceIdentity {device_id, mac, public_key, cert_info, enrolled_at}
         ↓
Device later connects → Authentication Server uses enrollment record
```

### Authentication mechanisms

**Certificate/Public-Key Authentication** (strong):
- Device proves possession of private key via challenge-response
- Server generates random challenge, device signs with private key
- Server verifies signature using registered public key
- MAC allowlisting is a weaker, non-cryptographic mechanism that should not be conflated with certificate authentication

**MAC Allowlisting** (weaker):
- Device is trusted because its MAC is on an allow list
- NO cryptographic proof of possession
- Easily spoofed
- Documented via `DeviceIdentity::allowlisted` and `AuthenticationResult::mechanism == "mac_allowlist"`

## 7. Phase 1 — Device Verification

**Objective:** given device discovery information and identity/authentication results, produce an authoritative TrustDecision.

```
DEVICE CONNECTED
      │
      ▼
Device Discovery ──► DeviceProfile
      │ (MAC, IP, hostname, vendor, DHCP)
      │
      ▼
Enrollment Registry Lookup:
      ├─ Unknown MAC ──► QUARANTINED (no enrolled identity found)
      ▼
Candidate DeviceIdentity
      │
      ▼
Authentication Flow
   ├─ NetworkIdentity   (MAC allowlist check)
   ├─ CryptoIdentity    (certificate verification via IAuthProvider)
   └─ PostureIdentity   (optional, architecture-only for now)
      │
      ▼
IAuthProvider::authenticate(DeviceProfile, DeviceIdentity)
      │
      ▼
AuthenticationResult = {success, mechanism, signature, failure_reason}
      │
      ▼
TrustPolicy.evaluate(DeviceProfile, AuthenticationResult, DeviceIdentity)
      │
      ├─ NON_TRUSTED ──► DeviceState::QUARANTINED
      │                  (policy: unknown device, auth failed, revoked, etc.)
      ▼
      TRUSTED ─────► DeviceState::AUTHORIZED
                     (cryptographically verified + policy approved)
```

`TrustPolicy` in Phase 1 is **deterministic rules**, not a numeric score:

```cpp
TrustDecision TrustPolicy::evaluate(const DeviceProfile& observed,
                                    const AuthenticationResult& auth,
                                    const DeviceIdentity& enrolled) {
    // Unknown device (no enrollment record)
    if (enrolled.device_id.empty()) 
        return {TrustLevel::NON_TRUSTED, "unknown device - not enrolled", now()};
    
    // Failed authentication
    if (!auth.success)  
        return {TrustLevel::NON_TRUSTED, auth.failure_reason.value_or("auth failed"), now()};
    
    // Revoked identity
    if (enrolled.enrolled_at < revocation_cutoff)
        return {TrustLevel::NON_TRUSTED, "identity revoked", now()};
    
    // Successfully authenticated
    return {TrustLevel::TRUSTED, "cryptographically verified", now()};
}
```

Do not add a numeric trust score in Phase 1. That's premature — save scoring for Phase 2's threat engine, which has a genuinely different job (aggregating many weak signals over time, not making a single point-in-time decision).

## 8. Phase 2 — Trusted-Device Defence

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

## 9. Detector build order

Build and fully test each tier before starting the next. Do not parallelize this — a working port-scan detector with full tests teaches you the pattern for the other eleven.

**Tier 1** (build first): port scanning, ARP spoofing, rogue DHCP, high packet rate.
**Tier 2**: suspicious HTTP, SMB probing, DNS anomalies, protocol anomalies.
**Tier 3**: C2-like beaconing, reconnaissance patterns, MAC/IP spoofing, LLMNR/NBNS poisoning.

## 10. Simulation layer

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

## 11. State machine

```
DISCONNECTED → IDENTIFIED ─┬─► AUTHENTICATING ─┬─► AUTHENTICATED ─┬─► TRUSTED → AUTHORIZED ─┬─► (stays, Phase 2 monitors)
                            │                    │                 │
                            │                    │                 └─► QUARANTINED ← (Phase 2 detects threat)
                            │                    ▼
                            └─► QUARANTINED    REVOKED ← (admin action or credential compromise)
                                                   │
                                                   └─► LOCKDOWN ← (severe threat during monitor)
```

One `DeviceStateMachine` per device, owned by `DeviceManager`. Phase 1 drives the left half of this diagram; Phase 2 drives the transition out of `AUTHORIZED` back into `QUARANTINED`/`LOCKDOWN` or `REVOKED`. No other code should mutate `DeviceState` directly — always go through the state machine so transitions stay valid and logged.

## 12. Enrollment Registry

The enrollment registry maps observed network identifiers to enrolled device identities:

- **Enrollment Store**: Database or in-memory map of MAC → DeviceIdentity
- **Lookup**: When a device is observed, check if its MAC has a DeviceIdentity
- **Unknown Device**: If no DeviceIdentity found, device is immediately QUARANTINED
- **Authenticated**: Only devices with valid enrollment records can proceed to authentication

Admin CLI for enrollment management:
```
security-jack-cli enroll-device --mac AA:BB:CC:DD:EE:FF --device-id my-laptop
security-jack-cli revoke-device --device-id my-laptop
security-jack-cli allow-mac --mac FF:EE:DD:CC:BB:AA
```

## 13. Build structure (CMake)

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

## 14. What NOT to do

- Don't give Phase 1 a job it doesn't have ("is this device malicious?" — that's Phase 2).
- Don't build a numeric trust score in Phase 1.
- Don't build more than one detector at a time.
- Don't let `core/` include anything from `simulation/` or `hardware/`.
- Don't invent hardware capabilities (e.g., pretending you can read OS posture over bare Ethernet) — represent the gap with an interface and a comment marking the boundary, not a fake implementation.
- Don't use `#ifdef ESP32` (or similar) inside `core/`, `phase1/`, `phase2/`.
- Don't conflate MAC address observations with cryptographic authentication results.
- Don't treat MAC allowlisting as equivalent to certificate authentication.

## 15. Key Distinctions

**DeviceProfile vs DeviceIdentity:**
- `DeviceProfile`: Purely observed network data (MAC, IP, hostname, vendor, first_seen). May be spoofed or shared.
- `DeviceIdentity`: Enrolled cryptographic identity established during provisioning. Stable, verifiable, cryptographically bound.

**IDENTIFICATION vs AUTHENTICATION:**
- Identification: "Which device is this?" — answered by observing network attributes (MAC, IP).
- Authentication: "Can this device prove it owns the enrolled identity?" — answered by cryptographic challenge-response or MAC allowlist (weaker).

**AUTHENTICATED vs AUTHORIZED:**
- AUTHENTICATED: The device has proven cryptographic possession of its enrolled credential.
- AUTHORIZED: TrustPolicy has decided the authenticated device may access the network.

**QUARANTINED vs REVOKED:**
- QUARANTINED: Device has restricted access (failed auth, threat detected, or unknown device). May become AUTHORIZED if issues resolved.
- REVOKED: Identity permanently no longer trusted (credential compromised, admin action). Must be re-enrolled.