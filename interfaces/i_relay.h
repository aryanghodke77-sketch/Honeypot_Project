// interfaces/i_relay.h
#pragma once

#include <string>

// Network access control abstraction
// Implementations: simulation/SimulatedRelay, hardware/ESP32Relay
// Controls whether device traffic is allowed or blocked
class IRelay {
public:
    virtual ~IRelay() = default;

    // Allow network access for device
    virtual void allow(const std::string& device_id) = 0;

    // Block/restrict network access for device
    virtual void block(const std::string& device_id) = 0;
};