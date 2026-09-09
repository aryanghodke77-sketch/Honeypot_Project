// phase2/detection_engine.h
#pragma once

#include <memory>
#include <vector>
#include "../interfaces/i_attack_detector.h"

// Phase 2: owns the set of attack detectors and fans every PacketEvent out to
// all of them (ARCHITECTURE.md section 8). Adding detector #7 never means
// touching detectors #1-6 or this control flow - only registerDetector().
class DetectionEngine {
public:
    void registerDetector(std::unique_ptr<IAttackDetector> detector);

    // Returns all SecurityEvents emitted by detectors for this packet.
    std::vector<SecurityEvent> onPacket(const PacketEvent& pkt);

    size_t detectorCount() const { return detectors_.size(); }

private:
    std::vector<std::unique_ptr<IAttackDetector>> detectors_;
};