// core/types/device_profile.h
#pragma once

#include <string>
#include <chrono>
#include <optional>

// Observed network information about a device
// Contains data extracted from network observations (packets, DHCP, etc.)
// Does NOT own stable identity; DeviceIdentity owns that
struct DeviceProfile {
    std::string mac;                 // observed MAC address (lookup key, not proof)
    std::string ip;                  // current IP address (may change)
    std::string hostname;           // may be spoofed
    std::string vendor;             // from OUI lookup (can be faked)
    std::optional<std::string> dhcp_option55; // parameter request list
    std::chrono::system_clock::time_point first_seen;
};