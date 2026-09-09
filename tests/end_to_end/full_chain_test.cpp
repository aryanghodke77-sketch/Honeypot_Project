// tests/end_to_end/full_chain_test.cpp
// End-to-end scenario test (WORKFLOW.md section 4): the full 15-step chain
//   connect -> identify -> authenticate -> trust -> authorize
//   -> normal traffic -> attack -> detected -> scored -> policy triggers
//   -> quarantine/lockdown
// plus the unknown-device quarantine path and a detector unit check.
#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

#include "core/types/packet_event.h"
#include "core/types/device_profile.h"
#include "core/identity/enrollment_registry.h"
#include "core/policy/trust_policy.h"
#include "core/state/device_state_machine.h"
#include "core/threat/threat_engine.h"
#include "simulation/console_logger.h"
#include "simulation/simulated_auth_provider.h"
#include "simulation/simulated_device.h"
#include "simulation/simulated_relay.h"
#include "core/crypto/sha256.h"
#include "phase1/verification_workflow.h"
#include "phase2/detection_engine.h"
#include "phase2/high_packet_rate_detector.h"
#include "phase2/response_engine.h"

using namespace std::chrono;

namespace {

const std::string TRUSTED_MAC = "AA:BB:CC:DD:EE:01";
const std::string UNKNOWN_MAC = "FF:FF:FF:FF:FF:02";
int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            std::cout << "  ok: " #cond "\n";                                \
        } else {                                                             \
            std::cout << "  FAIL: " #cond "\n";                              \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

PacketEvent make_pkt(const std::string& mac, int offset_ms) {
    PacketEvent p;
    p.src_mac = mac;
    p.dst_mac = "ff:ff:ff:ff:ff:ff";
    p.src_ip = "192.168.1.101";
    p.dst_ip = "192.168.1.1";
    p.protocol = Protocol::TCP;
    p.timestamp = system_clock::now() + milliseconds(offset_ms);
    return p;
}

DeviceProfile derive(const PacketEvent& p) {
    DeviceProfile prof;
    prof.mac = p.src_mac;
    prof.ip = p.src_ip;
    prof.first_seen = p.timestamp;
    return prof;
}

}  // namespace

int main() {
    std::cout << "Full-chain end-to-end test\n===========================\n\n";

    ConsoleLogger logger;
    SimulatedRelay relay(logger);

    // --- Crypto: SHA-256 / HMAC-SHA256 known vectors ---
    CHECK(crypto::sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(crypto::hmac_sha256_hex("key", "The quick brown fox jumps over the lazy dog") ==
          "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

    // --- Simulated device + enrollment registry ---
    const std::string device_secret = "simulated-device-secret-001";
    SimulatedDevice device(device_secret);

    EnrollmentRegistry registry;
    DeviceIdentity trusted;
    trusted.device_id = "trusted-laptop-001";
    trusted.mac = TRUSTED_MAC;
    trusted.public_key_jwk = device_secret;  // enrolled credential (simulated)
    CHECK(registry.enroll(trusted));
    CHECK(registry.lookup(TRUSTED_MAC) != nullptr);
    CHECK(registry.lookup(UNKNOWN_MAC) == nullptr);  // unknown not enrolled

    SimulatedAuthProvider auth;
    TrustPolicy policy;

    // --- Auth provider: challenge-response unit checks ---
    {
        DeviceProfile prof = derive(make_pkt(TRUSTED_MAC, 0));
        std::string challenge = "test-challenge";
        AuthenticationResult ok =
            auth.authenticate(prof, registry.lookup(TRUSTED_MAC), challenge,
                              device.sign(challenge));
        CHECK(ok.success);
        CHECK(ok.mechanism == "hmac_challenge_response");
        AuthenticationResult bad =
            auth.authenticate(prof, registry.lookup(TRUSTED_MAC), challenge,
                              device.sign("different-challenge"));  // wrong signature
        CHECK(!bad.success);
        CHECK(bad.failure_reason == "signature verification failed");
        AuthenticationResult unknown =
            auth.authenticate(prof, nullptr, challenge, "ignored");
        CHECK(!unknown.success);
    }

    // --- Phase 1: unknown device is quarantined immediately ---
    {
        DeviceStateMachine sm(&logger);
        VerificationWorkflow wf(registry, auth, policy, relay, sm, device, &logger);
        DeviceProfile unknown = derive(make_pkt(UNKNOWN_MAC, 0));
        CHECK(!wf.verify(unknown));
        CHECK(sm.state() == DeviceState::QUARANTINED);
    }

    // --- Phase 1: trusted device authorizes ---
    DeviceStateMachine trusted_sm(&logger);
    VerificationWorkflow wf(registry, auth, policy, relay, trusted_sm, device, &logger);
    DeviceProfile prof = derive(make_pkt(TRUSTED_MAC, 0));
    CHECK(wf.verify(prof));
    CHECK(trusted_sm.state() == DeviceState::AUTHORIZED);

    // State machine rejects invalid transitions.
    CHECK(!trusted_sm.transition(DeviceState::DISCONNECTED));

    // --- Detector unit check: fires once per window past threshold ---
    {
        HighPacketRateDetector d(20, milliseconds(1000));
        std::optional<SecurityEvent> evt;
        for (int i = 0; i < 19; ++i) {
            evt = d.onPacket(make_pkt(TRUSTED_MAC, 100 + i));
        }
        CHECK(!evt.has_value());  // below threshold
        evt = d.onPacket(make_pkt(TRUSTED_MAC, 200));
        CHECK(evt.has_value());   // 20th packet fires
        evt = d.onPacket(make_pkt(TRUSTED_MAC, 210));
        CHECK(!evt.has_value());  // already fired within window
    }

    // --- Phase 2: attack bursts escalate to lockdown ---
    {
        DetectionEngine engine;
        engine.registerDetector(std::make_unique<HighPacketRateDetector>());
        ThreatEngine threat;
        ResponseEngine response(relay, trusted_sm, logger);

        // Three bursts of 25 packets, ~1400ms apart (see main_sim.cpp).
        auto feed_burst = [&](int start_ms) {
            for (int i = 0; i < 25; ++i) {
                auto evts = engine.onPacket(make_pkt(TRUSTED_MAC, start_ms + i * 8));
                for (auto& e : evts) {
                    ThreatAssessment ta = threat.onEvent(e);
                    response.onAssessment(e.device_id, ta);
                }
            }
        };
        feed_burst(1000);
        CHECK(threat.assessment(TRUSTED_MAC).score >= 25);   // MEDIUM+ -> alert
        feed_burst(2400);
        feed_burst(3800);
        CHECK(threat.assessment(TRUSTED_MAC).score >= 75);   // CRITICAL
        CHECK(trusted_sm.state() == DeviceState::LOCKDOWN);
    }

    std::cout << "\n===========================\n";
    if (failures == 0) {
        std::cout << "All full-chain checks PASSED!\n";
        return 0;
    }
    std::cout << failures << " check(s) FAILED\n";
    return 1;
}