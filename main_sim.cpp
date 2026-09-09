// main_sim.cpp
// Top-level wiring - the ONLY place allowed to know which implementations
// (simulator vs future hardware) are in use. Runs the full chain from
// ARCHITECTURE.md section 11:
//   connect -> identify -> authenticate -> trust -> authorize
//   -> normal traffic -> attack -> detected -> scored -> policy triggers
//   -> quarantine/lockdown.
#include <iostream>
#include <memory>
#include <vector>

#include "core/types/packet_event.h"
#include "core/types/device_profile.h"
#include "core/types/device_identity.h"
#include "core/identity/enrollment_registry.h"
#include "core/policy/trust_policy.h"
#include "core/state/device_state_machine.h"
#include "core/threat/threat_engine.h"
#include "simulation/console_logger.h"
#include "simulation/simulated_ethernet.h"
#include "simulation/simulated_auth_provider.h"
#include "simulation/simulated_device.h"
#include "simulation/simulated_relay.h"
#include "phase1/verification_workflow.h"
#include "phase2/detection_engine.h"
#include "phase2/high_packet_rate_detector.h"
#include "phase2/response_engine.h"

using namespace std::chrono;

namespace {

const std::string TRUSTED_MAC = "AA:BB:CC:DD:EE:01";
const std::string UNKNOWN_MAC = "FF:FF:FF:FF:FF:02";

PacketEvent make_pkt(const std::string& mac, int offset_ms) {
    PacketEvent p;
    p.src_mac = mac;
    p.dst_mac = "ff:ff:ff:ff:ff:ff";
    p.src_ip = (mac == TRUSTED_MAC) ? "192.168.1.101" : "192.168.1.222";
    p.dst_ip = "192.168.1.1";
    p.protocol = Protocol::TCP;
    p.timestamp = system_clock::now() + milliseconds(offset_ms);
    return p;
}

// Phase 1 discovery: derive an observed DeviceProfile from a packet.
DeviceProfile derive(const PacketEvent& p) {
    DeviceProfile prof;
    prof.mac = p.src_mac;
    prof.ip = p.src_ip;
    prof.first_seen = p.timestamp;
    return prof;
}

const char* eventName(EventType t) {
    switch (t) {
        case EventType::PORT_SCAN_DETECTED:      return "PORT_SCAN";
        case EventType::ARP_SPOOF_DETECTED:      return "ARP_SPOOF";
        case EventType::ROGUE_DHCP_DETECTED:     return "ROGUE_DHCP";
        case EventType::HIGH_PACKET_RATE_DETECTED: return "HIGH_PACKET_RATE";
    }
    return "?";
}

const char* levelName(ThreatLevel l) {
    switch (l) {
        case ThreatLevel::NORMAL:   return "NORMAL";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
    }
    return "?";
}

// Deterministic scenario:
//   trusted device connects, some normal traffic, then THREE bursts of 25
//   packets (~200ms each, >1200ms apart) - each burst trips the
//   high-packet-rate detector once (threshold 20/1000ms window).
//   An unknown device appears at the end (Phase 1 quarantine path).
std::vector<PacketEvent> build_scenario() {
    std::vector<PacketEvent> s;
    auto burst = [&](int start_ms) {
        for (int i = 0; i < 25; ++i) {
            s.push_back(make_pkt(TRUSTED_MAC, start_ms + i * 8));
        }
    };
    s.push_back(make_pkt(TRUSTED_MAC, 0));    // connect / discovery
    s.push_back(make_pkt(TRUSTED_MAC, 100));  // normal traffic
    s.push_back(make_pkt(TRUSTED_MAC, 200));
    s.push_back(make_pkt(TRUSTED_MAC, 300));
    burst(1000);                              // attack burst 1
    s.push_back(make_pkt(TRUSTED_MAC, 1400)); // brief normal
    burst(2400);                              // attack burst 2
    burst(3800);                              // attack burst 3
    s.push_back(make_pkt(UNKNOWN_MAC, 5000)); // unknown device
    return s;
}

}  // namespace

int main() {
    ConsoleLogger logger;
    SimulatedRelay relay(logger);

    // The simulated device holds its own private key; the enrolled registry
    // record holds the matching key used to verify its signatures.
    const std::string device_secret = "simulated-device-secret-001";
    SimulatedDevice device(device_secret);

    // Enrollment: one trusted device in the registry.
    EnrollmentRegistry registry;
    DeviceIdentity trusted;
    trusted.device_id = "trusted-laptop-001";
    trusted.mac = TRUSTED_MAC;
    trusted.public_key_jwk = device_secret;  // enrolled credential (simulated)
    registry.enroll(trusted);

    SimulatedAuthProvider auth;
    TrustPolicy policy;

    // Phase 1 for the trusted device.
    DeviceStateMachine trusted_sm(&logger);
    VerificationWorkflow workflow(registry, auth, policy, relay, trusted_sm, device, &logger);

    // Phase 2 for the trusted device.
    DetectionEngine engine;
    engine.registerDetector(std::make_unique<HighPacketRateDetector>());
    ThreatEngine threat;
    ResponseEngine response(relay, trusted_sm, logger);

    std::cout << "=== Security Jack: full-chain simulation ===\n\n";

    SimulatedEthernet sim(build_scenario());
    sim.start();

    bool trusted_verified = false;
    bool unknown_checked = false;

    while (auto pkt = sim.poll()) {
        // Phase 1 (per newly seen device).
        if (!trusted_verified && pkt->src_mac == TRUSTED_MAC) {
            trusted_verified = true;
            bool ok = workflow.verify(derive(*pkt));
            std::cout << "[SIM] PHASE 1: trusted device  " << TRUSTED_MAC << " -> "
                      << (ok ? "AUTHORIZED" : "NOT TRUSTED")
                      << "  [state: " << DeviceStateMachine::name(trusted_sm.state()) << "]\n";
        }
        if (!unknown_checked && pkt->src_mac == UNKNOWN_MAC) {
            unknown_checked = true;
            DeviceStateMachine unknown_sm(&logger);
            VerificationWorkflow wf2(registry, auth, policy, relay, unknown_sm, device, &logger);
            bool ok = wf2.verify(derive(*pkt));
            std::cout << "[SIM] PHASE 1: unknown device   " << UNKNOWN_MAC << " -> "
                      << (ok ? "AUTHORIZED" : "NOT TRUSTED")
                      << "  [state: " << DeviceStateMachine::name(unknown_sm.state()) << "]\n";
        }

        // Phase 2 (continuous monitoring).
        for (auto& evt : engine.onPacket(*pkt)) {
            ThreatAssessment ta = threat.onEvent(evt);
            std::cout << "[SIM] DETECTED: " << eventName(evt.type) << " | "
                      << evt.description << "\n";
            std::cout << "[SIM] THREAT:   " << evt.device_id
                      << " score=" << ta.score << " level=" << levelName(ta.level) << "\n";
            response.onAssessment(evt.device_id, ta);
        }
    }

    std::cout << "\n=== RESULT: trusted device final state = "
              << DeviceStateMachine::name(trusted_sm.state()) << " ===\n";
    return 0;
}