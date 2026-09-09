// phase2/detection_engine.cpp
#include "detection_engine.h"

void DetectionEngine::registerDetector(std::unique_ptr<IAttackDetector> detector) {
    detectors_.push_back(std::move(detector));
}

std::vector<SecurityEvent> DetectionEngine::onPacket(const PacketEvent& pkt) {
    std::vector<SecurityEvent> events;
    for (auto& detector : detectors_) {
        if (auto evt = detector->onPacket(pkt)) {
            events.push_back(std::move(*evt));
        }
    }
    return events;
}