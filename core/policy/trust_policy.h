// core/policy/trust_policy.h
#pragma once

#include <chrono>
#include "../types/device_profile.h"
#include "../types/device_identity.h"
#include "../types/authentication_result.h"
#include "../types/trust_decision.h"

// Phase 1: deterministic trust policy (ARCHITECTURE.md section 7)
// Rules, not a numeric score. Numeric scoring belongs to Phase 2's ThreatEngine.
class TrustPolicy {
public:
    TrustPolicy() = default;

    // Decide whether a device should be trusted.
    //   observed - network-discovered device data
    //   auth     - result of the authentication attempt
    //   enrolled - enrolled identity, nullptr if unknown/unenrolled
    TrustDecision evaluate(const DeviceProfile& observed,
                           const AuthenticationResult& auth,
                           const DeviceIdentity* enrolled) const;

    // Identities enrolled before this cutoff count as revoked.
    // Default: epoch -> nothing is revoked.
    void set_revocation_cutoff(std::chrono::system_clock::time_point cutoff);

private:
    std::chrono::system_clock::time_point revocation_cutoff_{};
};