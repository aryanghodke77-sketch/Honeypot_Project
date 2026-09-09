// simulation/simulated_auth_provider.cpp
#include "simulated_auth_provider.h"
#include "../core/crypto/sha256.h"

AuthenticationResult SimulatedAuthProvider::authenticate(
    const DeviceProfile& observed,
    const DeviceIdentity* enrolled,
    const std::string& challenge,
    const std::string& signature) {
    (void)observed;  // verification keys off the enrollment record + signature

    AuthenticationResult result;
    result.mechanism = "hmac_challenge_response";

    // Unknown / unenrolled device - never authenticates.
    if (enrolled == nullptr) {
        result.success = false;
        result.failure_reason = "unknown device - not enrolled";
        return result;
    }

    // Enrolled but no registered credential - cannot verify anything.
    if (enrolled->public_key_jwk.empty()) {
        result.success = false;
        result.failure_reason = "no enrolled credential";
        return result;
    }

    // Recompute the expected signature from the enrolled key and challenge,
    // then compare. (Constant-time compare is a production concern; the
    // simulator uses a plain comparison.)
    std::string expected = crypto::hmac_sha256_hex(enrolled->public_key_jwk, challenge);
    if (expected != signature) {
        result.success = false;
        result.failure_reason = "signature verification failed";
        return result;
    }

    result.success = true;
    result.signature = signature;  // proof echoed for audit/logging
    return result;
}