// phase2/response_engine.h
#pragma once

#include <string>
#include <unordered_map>
#include "../interfaces/i_relay.h"
#include "../interfaces/i_logger.h"
#include "../core/types/threat_assessment.h"
#include "../core/state/device_state_machine.h"

// Phase 2: consumes ThreatAssessments and maps them to responses
// (ARCHITECTURE.md section 8):
//   NORMAL/LOW  -> log only (keep AUTHORIZED)
//   MEDIUM      -> ALERT
//   HIGH        -> QUARANTINE (revoke trust, block via relay)
//   CRITICAL    -> LOCKDOWN (complete isolation)
// Actions escalate per device and are applied at most once per level.
class ResponseEngine {
public:
    ResponseEngine(IRelay& relay, DeviceStateMachine& state_machine, ILogger& logger);

    void onAssessment(const std::string& device_id, const ThreatAssessment& assessment);

private:
    enum class ResponseLevel { ALLOWED = 0, ALERTED = 1, QUARANTINED = 2, LOCKDOWN = 3 };

    IRelay& relay_;
    DeviceStateMachine& state_machine_;
    ILogger& logger_;
    std::unordered_map<std::string, ResponseLevel> responses_;
};