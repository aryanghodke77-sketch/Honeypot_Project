// simulation/simulated_device.h
#pragma once

#include <string>
#include "../interfaces/i_challenge_signer.h"

// IChallengeSigner implementation (simulator)
// A simulated device holding its own private key (an in-memory string for
// now; a secure element later). Signs challenges with HMAC-SHA256 - the
// crypto is real, the key material is simulated.
// The corresponding secret is registered in DeviceIdentity::public_key_jwk
// so the auth provider can verify the signature.
class SimulatedDevice : public IChallengeSigner {
public:
    explicit SimulatedDevice(std::string private_key);

    std::string sign(const std::string& challenge) const override;

private:
    std::string private_key_;
};