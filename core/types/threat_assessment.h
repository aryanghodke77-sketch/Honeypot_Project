// core/types/threat_assessment.h
#pragma once

#include <string>
#include <vector>

// Phase 2: Threat level enumeration
// Used by ThreatEngine to score devices based on detected events
enum class ThreatLevel {
    NORMAL,    // No threats detected
    LOW,       // Minor anomalies
    MEDIUM,    // Concerning activity
    HIGH,      // Clear threat indicators
    CRITICAL   // Immediate action required
};

// Phase 2: Aggregated threat assessment per device
// Output of ThreatEngine, input to ResponseEngine
struct ThreatAssessment {
    ThreatLevel level;
    int score;                                  // 0-100, detectors contribute deltas
    std::vector<std::string> contributing_events; // SecurityEvent IDs
};