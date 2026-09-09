// phase2/high_packet_rate_detector.h
#pragma once

#include <chrono>
#include <deque>
#include <map>
#include <string>
#include "../interfaces/i_attack_detector.h"

// Tier 1 detector: high packet rate (ARCHITECTURE.md section 9)
// Triggers when a source MAC emits >= threshold packets within a sliding
// time window. Stateless-in, stateful-out: keeps per-source timestamps.
class HighPacketRateDetector : public IAttackDetector {
public:
    HighPacketRateDetector(size_t threshold = 20,
                           std::chrono::milliseconds window = std::chrono::milliseconds(1000));

    std::optional<SecurityEvent> onPacket(const PacketEvent& pkt) override;
    std::string name() const override { return "high_packet_rate"; }

private:
    struct SourceState {
        std::deque<std::chrono::system_clock::time_point> times;
        std::optional<std::chrono::system_clock::time_point> last_fire;
    };

    size_t threshold_;
    std::chrono::milliseconds window_;
    std::map<std::string, SourceState> per_source_;
    uint64_t event_counter_ = 0;
};