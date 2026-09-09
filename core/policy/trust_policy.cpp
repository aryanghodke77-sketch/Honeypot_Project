// core/policy/trust_policy.cpp
#include "trust_policy.h"

void TrustPolicy::set_revocation_cutoff(std::chrono::system_clock::time_point cutoff) {
    revocation_cutoff_ = cutoff;
}

TrustDecision TrustPolicy::evaluate(const DeviceProfile& observed,
                                    const AuthenticationResult& auth,
                                    const DeviceIdentity* enrolled) const {
    (void)observed;  // policy rules key off enrollment + auth result
    auto now = std::chrono::system_clock::now();

    // Unknown device (no enrollment record) - never trusted.
    if (enrolled == nullptr) {
        return {TrustLevel::NON_TRUSTED, "unknown device - not enrolled", now};
    }

    // Failed authentication - never trusted.
    if (!auth.success) {
        return {TrustLevel::NON_TRUSTED,
                auth.failure_reason.value_or("auth failed"), now};
    }

    // Revoked identity - never trusted.
    if (enrolled->enrolled_at < revocation_cutoff_) {
        return {TrustLevel::NON_TRUSTED, "identity revoked", now};
    }

    // Successfully authenticated.
    return {TrustLevel::TRUSTED, "cryptographically verified", now};
}