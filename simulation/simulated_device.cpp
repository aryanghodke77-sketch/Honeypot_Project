// simulation/simulated_device.cpp
#include "simulated_device.h"
#include "../core/crypto/sha256.h"

SimulatedDevice::SimulatedDevice(std::string private_key)
    : private_key_(std::move(private_key)) {}

std::string SimulatedDevice::sign(const std::string& challenge) const {
    return crypto::hmac_sha256_hex(private_key_, challenge);
}