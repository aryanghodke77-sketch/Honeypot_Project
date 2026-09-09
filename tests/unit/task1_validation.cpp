// tests/unit/task1_validation.cpp
// Task 1 validation test: verifies all data models and interfaces compile and are usable
// This is a structural test, not behavioral - Task 1 only creates headers

#include <cassert>
#include <iostream>
#include <chrono>
#include <string>

// Include all core/types headers
#include "core/types/protocol.h"
#include "core/types/packet_event.h"
#include "core/types/device_profile.h"
#include "core/types/device_identity.h"
#include "core/types/authentication_result.h"
#include "core/types/trust_decision.h"
#include "core/types/device_state.h"
#include "core/types/threat_assessment.h"
#include "core/types/security_event.h"

// Include all interfaces headers
#include "interfaces/i_logger.h"
#include "interfaces/i_relay.h"
#include "interfaces/i_ethernet_source.h"
#include "interfaces/i_auth_provider.h"

using namespace std::chrono;

int main() {
    std::cout << "Task 1 Validation Test\n";
    std::cout << "======================\n\n";

    // Test 1: Protocol enum
    std::cout << "Test 1: Protocol enum... ";
    Protocol proto = Protocol::TCP;
    assert(proto == Protocol::TCP);
    assert(Protocol::UNKNOWN != Protocol::TCP);
    std::cout << "PASS\n";

    // Test 2: PacketEvent creation
    std::cout << "Test 2: PacketEvent creation... ";
    auto now = system_clock::now();
    PacketEvent pkt;
    pkt.src_mac = "00:11:22:33:44:55";
    pkt.dst_mac = "ff:ff:ff:ff:ff:ff";
    pkt.src_ip = "192.168.1.100";
    pkt.dst_ip = "192.168.1.1";
    pkt.src_port = 80;
    pkt.dst_port = 443;
    pkt.protocol = Protocol::TCP;
    pkt.timestamp = now;
    assert(pkt.src_mac == "00:11:22:33:44:55");
    assert(pkt.protocol == Protocol::TCP);
    assert(pkt.payload.empty());
    std::cout << "PASS\n";

    // Test 3: DeviceProfile creation
    std::cout << "Test 3: DeviceProfile creation... ";
    DeviceProfile profile;
    profile.mac = "00:11:22:33:44:55";
    profile.ip = "192.168.1.100";
    profile.hostname = "laptop-001";
    profile.vendor = "Apple Inc.";
    profile.first_seen = now;
    assert(profile.mac == "00:11:22:33:44:55");
    assert(profile.hostname == "laptop-001");
    std::cout << "PASS\n";

    // Test 4: DeviceIdentity creation
    std::cout << "Test 4: DeviceIdentity creation... ";
    DeviceIdentity identity;
    identity.device_id = "dev-abc123";
    identity.mac = "00:11:22:33:44:55";
    identity.public_key_jwk = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    identity.allowlisted = false;
    identity.enrolled_at = now;
    assert(identity.device_id == "dev-abc123");
    assert(identity.allowlisted == false);
    std::cout << "PASS\n";

    // Test 5: AuthenticationResult creation
    std::cout << "Test 5: AuthenticationResult creation... ";
    AuthenticationResult auth;
    auth.success = true;
    auth.mechanism = "certificate";
    assert(auth.success == true);
    assert(auth.mechanism == "certificate");

    // Test auth failure
    AuthenticationResult auth_fail;
    auth_fail.success = false;
    auth_fail.mechanism = "mac_allowlist";
    assert(auth_fail.success == false);
    assert(auth_fail.mechanism == "mac_allowlist");
    std::cout << "PASS\n";

    // Test 6: TrustDecision creation
    std::cout << "Test 6: TrustDecision creation... ";
    TrustDecision decision;
    decision.level = TrustLevel::TRUSTED;
    decision.reason = "network identity + credential verified";
    decision.decided_at = now;
    assert(decision.level == TrustLevel::TRUSTED);
    assert(!decision.reason.empty());

    // Test non-trusted decision
    TrustDecision non_trusted;
    non_trusted.level = TrustLevel::NON_TRUSTED;
    non_trusted.reason = "unknown device";
    assert(non_trusted.level == TrustLevel::NON_TRUSTED);
    std::cout << "PASS\n";

    // Test 7: DeviceState enum
    std::cout << "Test 7: DeviceState enum... ";
    DeviceState state = DeviceState::DISCONNECTED;
    assert(state == DeviceState::DISCONNECTED);
    state = DeviceState::AUTHORIZED;
    assert(state == DeviceState::AUTHORIZED);
    state = DeviceState::QUARANTINED;
    assert(state == DeviceState::QUARANTINED);
    state = DeviceState::LOCKDOWN;
    assert(state == DeviceState::LOCKDOWN);
    state = DeviceState::REVOKED;
    assert(state == DeviceState::REVOKED);
    std::cout << "PASS\n";

    // Test 8: ThreatAssessment creation
    std::cout << "Test 8: ThreatAssessment creation... ";
    ThreatAssessment threat;
    threat.level = ThreatLevel::NORMAL;
    threat.score = 0;
    assert(threat.level == ThreatLevel::NORMAL);
    assert(threat.score == 0);
    assert(threat.contributing_events.empty());
    std::cout << "PASS\n";

    // Test 9: SecurityEvent creation
    std::cout << "Test 9: SecurityEvent creation... ";
    SecurityEvent event;
    event.id = "evt-001";
    event.device_id = "dev-abc123";
    event.type = EventType::PORT_SCAN_DETECTED;
    event.description = "Port scan detected from 192.168.1.100";
    event.timestamp = now;
    assert(event.id == "evt-001");
    assert(event.type == EventType::PORT_SCAN_DETECTED);
    std::cout << "PASS\n";

    // Test 10: Interface abstract classes can be referenced
    std::cout << "Test 10: Interface abstract classes... ";
    ILogger* logger = nullptr;
    IRelay* relay = nullptr;
    IEthernetSource* ethernet = nullptr;
    IAuthProvider* auth_provider = nullptr;
    assert(logger == nullptr);
    assert(relay == nullptr);
    assert(ethernet == nullptr);
    assert(auth_provider == nullptr);
    std::cout << "PASS\n";

    // Test 11: DeviceIdentity null pointer support (unknown device)
    std::cout << "Test 11: Null DeviceIdentity support... ";
    const DeviceIdentity* null_identity = nullptr;
    assert(null_identity == nullptr);
    // This represents an unknown/unenrolled device
    std::cout << "PASS\n";

    // Test 12: MAC is NOT device_id
    std::cout << "Test 12: MAC vs device_id distinction... ";
    DeviceProfile unknown_profile;
    unknown_profile.mac = "AA:BB:CC:DD:EE:FF";
    // DeviceProfile does NOT have device_id field (removed per architecture)
    // DeviceIdentity owns device_id, not DeviceProfile
    DeviceIdentity enrolled_identity;
    enrolled_identity.device_id = "dev-xyz789";
    enrolled_identity.mac = "AA:BB:CC:DD:EE:FF";
    // MAC is used for lookup, NOT as the stable identity
    assert(unknown_profile.mac == enrolled_identity.mac);
    assert(unknown_profile.mac != enrolled_identity.device_id);
    std::cout << "PASS\n";

    std::cout << "\n======================\n";
    std::cout << "All Task 1 validation tests PASSED!\n";
    std::cout << "======================\n";

    return 0;
}