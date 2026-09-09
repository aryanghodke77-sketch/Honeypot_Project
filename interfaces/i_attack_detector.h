// interfaces/i_attack_detector.h
#pragma once

#include <optional>
#include <string>
#include "../core/types/packet_event.h"
#include "../core/types/security_event.h"

// Phase 2: attack detector abstraction (ARCHITECTURE.md section 8)
// Each detector is independent and stateless-in, stateful-out:
//   - reads PacketEvent fields it cares about
//   - emits a SecurityEvent when its trigger condition fires
// Implementations: phase2/high_packet_rate_detector, future detectors
class IAttackDetector {
public:
    virtual ~IAttackDetector() = default;

    // Examine one packet; return a SecurityEvent if the detector triggers.
    virtual std::optional<SecurityEvent> onPacket(const PacketEvent& pkt) = 0;

    // Detector name for logging/diagnostics.
    virtual std::string name() const = 0;
};