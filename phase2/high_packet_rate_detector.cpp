// phase2/high_packet_rate_detector.cpp
#include "high_packet_rate_detector.h"

HighPacketRateDetector::HighPacketRateDetector(size_t threshold,
                                               std::chrono::milliseconds window)
    : threshold_(threshold), window_(window) {}

std::optional<SecurityEvent> HighPacketRateDetector::onPacket(const PacketEvent& pkt) {
    SourceState& s = per_source_[pkt.src_mac];

    // Drop timestamps outside the window.
    auto cutoff = pkt.timestamp - window_;
    while (!s.times.empty() && s.times.front() < cutoff) {
        s.times.pop_front();
    }
    s.times.push_back(pkt.timestamp);

    // Fire at most once per window.
    bool window_elapsed = !s.last_fire ||
                          (pkt.timestamp - *s.last_fire) >= window_;
    if (s.times.size() < threshold_ || !window_elapsed) {
        return std::nullopt;
    }

    s.last_fire = pkt.timestamp;

    SecurityEvent evt;
    evt.id = "evt-" + std::to_string(++event_counter_);
    evt.device_id = pkt.src_mac;  // observational device handle for now
    evt.type = EventType::HIGH_PACKET_RATE_DETECTED;
    evt.description = "High packet rate from " + pkt.src_mac + ": " +
                      std::to_string(s.times.size()) + " packets in " +
                      std::to_string(window_.count()) + "ms window";
    evt.timestamp = pkt.timestamp;
    return evt;
}