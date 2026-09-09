// interfaces/i_challenge_signer.h
#pragma once

#include <string>

// Device-side capability for challenge-response authentication
// (ARCHITECTURE.md section 6 - certificate/public-key authentication).
// The device proves possession of its private key by signing the challenge.
// Implementations:
//   simulation/SimulatedDevice   - signs with an in-memory key (now)
//   hardware/secure element      - signs with a protected keystore (later)
// The verifier (IAuthProvider) never sees the private key - only the signature.
class IChallengeSigner {
public:
    virtual ~IChallengeSigner() = default;

    // Sign `challenge` with the device's private key. Returns hex signature.
    virtual std::string sign(const std::string& challenge) const = 0;
};