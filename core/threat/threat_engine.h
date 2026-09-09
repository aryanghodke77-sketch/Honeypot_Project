// core/threat/threat_engine.h
#pragma once

#include <string>
#include <unordered_map>
#include "../types/security_event.h"
#include "../types/threat_assessment.h"

// Phase 2: consumes SecurityEvents (not raw packets) and maintains a per-device
// score (ARCHITECTURE.md section 8). Scoring is a simple, inspectable table of
// event-type -> point delta with time decay - not a black box.
class ThreatEngine {
public:
    // Score a security event for its device and return the updated assessment.
    ThreatAssessment onEvent(const SecurityEvent& event);

    // Current assessment for a device (no decay applied).
    ThreatAssessment assessment(const std::string& device_id) const;

    // Event-type -> point delta (0-100 scale). Extend as detectors are added.
    static int delta(EventType type);

    // Score -> level mapping.
    static ThreatLevel level_for(int score);

private:
    struct DeviceScore {
        int score = 0;
        std::chrono::system_clock::time_point last_event{};
        std::vector<std::string> contributing;  // most recent SecurityEvent ids
    };
    std::unordered_map<std::string, DeviceScore> devices_;

    // Decay score by elapsed time (1 point per second since the last event).
    void apply_decay(DeviceScore& s) const;
};