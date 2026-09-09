// core/threat/threat_engine.cpp
#include "threat_engine.h"
#include <algorithm>

int ThreatEngine::delta(EventType type) {
    switch (type) {
        case EventType::HIGH_PACKET_RATE_DETECTED: return 30;
        // Tier 1 additions later: port scan, ARP spoof, rogue DHCP
        case EventType::PORT_SCAN_DETECTED:        return 30;
        case EventType::ARP_SPOOF_DETECTED:        return 30;
        case EventType::ROGUE_DHCP_DETECTED:       return 30;
    }
    return 25;
}

ThreatLevel ThreatEngine::level_for(int score) {
    if (score <= 0)   return ThreatLevel::NORMAL;
    if (score < 25)   return ThreatLevel::LOW;
    if (score < 50)   return ThreatLevel::MEDIUM;
    if (score < 75)   return ThreatLevel::HIGH;
    return ThreatLevel::CRITICAL;
}

void ThreatEngine::apply_decay(DeviceScore& s) const {
    auto now = std::chrono::system_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now - s.last_event)
                          .count();
    if (elapsed_ms > 0) {
        s.score = std::max(0, s.score - static_cast<int>(elapsed_ms / 1000));
    }
}

ThreatAssessment ThreatEngine::onEvent(const SecurityEvent& event) {
    DeviceScore& s = devices_[event.device_id];

    apply_decay(s);
    s.score = std::min(100, s.score + delta(event.type));
    s.last_event = event.timestamp;

    s.contributing.push_back(event.id);
    if (s.contributing.size() > 5) {
        s.contributing.erase(s.contributing.begin());
    }

    return {level_for(s.score), s.score, s.contributing};
}

ThreatAssessment ThreatEngine::assessment(const std::string& device_id) const {
    auto it = devices_.find(device_id);
    if (it == devices_.end()) {
        return {ThreatLevel::NORMAL, 0, {}};
    }
    return {level_for(it->second.score), it->second.score, it->second.contributing};
}