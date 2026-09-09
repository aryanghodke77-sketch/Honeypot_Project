// core/identity/enrollment_registry.h
#pragma once

#include <string>
#include <unordered_map>
#include "../types/device_identity.h"

// Enrollment registry (ARCHITECTURE.md section 12)
// Maps observed network identifiers (MAC) to enrolled DeviceIdentity records.
// Lookup: when a device is observed, check if its MAC has a DeviceIdentity.
// Unknown MAC -> nullptr -> device is immediately QUARANTINED upstream.
// Pure core data - no interface or simulation dependencies.
class EnrollmentRegistry {
public:
    // Register an enrolled identity. Returns false if the MAC is already enrolled.
    bool enroll(const DeviceIdentity& identity);

    // Look up by MAC. Returns nullptr if the device is not enrolled.
    const DeviceIdentity* lookup(const std::string& mac) const;

    // Permanently remove an identity (revocation). Returns false if unknown.
    bool revoke(const std::string& device_id);

    size_t size() const;

private:
    std::unordered_map<std::string, DeviceIdentity> by_mac_;
};