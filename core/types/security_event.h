// core/types/security_event.h
#pragma once

#include <string>
#include <chrono>

// Phase 2: Type of security event detected by attack detectors
enum class EventType {
    PORT_SCAN_DETECTED,
    ARP_SPOOF_DETECTED,
    ROGUE_DHCP_DETECTED,
    HIGH_PACKET_RATE_DETECTED
    // Tier 2/3 events added incrementally
};

// Phase 2: Security event output from attack detectors
// Device owns event detection, ThreatEngine scores events
// Does NOT mutate DeviceState directly; only emits event
struct SecurityEvent {
    std::string id;              // unique identifier
    std::string device_id;       // which device generated this event
    EventType type;              // what kind of attack
    std::string description;     // human-readable description
    std::chrono::system_clock::time_point timestamp;
};