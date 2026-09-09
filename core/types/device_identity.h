// core/types/device_identity.h
#pragma once

#include <string>
#include <chrono>
#include <optional>

// Enrolled logical identity for a device
// This represents the identity established during device enrollment/provisioning
// Owned by: Identity Server or Enrollment Registry
// MAC is used as lookup key, NOT the stable device_id
// A device may be observed (DeviceProfile) without having an enrolled DeviceIdentity
struct DeviceIdentity {
    std::string device_id;       // stable internal id assigned during enrollment
    std::string mac;              // associated MAC (used for identification, not auth proof)
    std::string public_key_jwk;   // public key in JWK format (for challenge-response)
    std::optional<std::string> certificate_serial;
    std::chrono::system_clock::time_point enrolled_at;
    bool allowlisted;            // legacy MAC allowlist (weaker mechanism)
};