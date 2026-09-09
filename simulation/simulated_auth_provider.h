// simulation/simulated_auth_provider.h
#pragma once

#include <string>
#include "../interfaces/i_auth_provider.h"

// IAuthProvider implementation (simulator)
// Verifies the device's HMAC-SHA256 signature over the challenge against the
// enrolled key in DeviceIdentity::public_key_jwk (real crypto, simulated key
// material). Mechanism: "hmac_challenge_response".
// The weaker MAC-allowlist mechanism is NOT accepted here - enrollment with
// no registered key cannot authenticate.
class SimulatedAuthProvider : public IAuthProvider {
public:
    AuthenticationResult authenticate(
        const DeviceProfile& observed,
        const DeviceIdentity* enrolled,
        const std::string& challenge,
        const std::string& signature) override;
};