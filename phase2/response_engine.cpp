// phase2/response_engine.cpp
#include "response_engine.h"

ResponseEngine::ResponseEngine(IRelay& relay, DeviceStateMachine& state_machine,
                               ILogger& logger)
    : relay_(relay), state_machine_(state_machine), logger_(logger) {}

void ResponseEngine::onAssessment(const std::string& device_id,
                                  const ThreatAssessment& assessment) {
    ResponseLevel current = responses_[device_id];  // default ALLOWED

    switch (assessment.level) {
        case ThreatLevel::NORMAL:
        case ThreatLevel::LOW:
            logger_.log(LogLevel::INFO,
                        "RESPONSE: " + device_id + " stays authorized (score " +
                            std::to_string(assessment.score) + ")");
            return;

        case ThreatLevel::MEDIUM:
            if (current < ResponseLevel::ALERTED) {
                logger_.log(LogLevel::WARNING,
                            "RESPONSE: ALERT - " + device_id + " suspicious activity (score " +
                                std::to_string(assessment.score) + ")");
                responses_[device_id] = ResponseLevel::ALERTED;
            }
            return;

        case ThreatLevel::HIGH:
            if (current < ResponseLevel::QUARANTINED) {
                logger_.log(LogLevel::ERROR,
                            "RESPONSE: QUARANTINE - " + device_id + " (score " +
                                std::to_string(assessment.score) + ")");
                relay_.block(device_id);
                state_machine_.transition(DeviceState::QUARANTINED);
                responses_[device_id] = ResponseLevel::QUARANTINED;
            }
            return;

        case ThreatLevel::CRITICAL:
            if (current < ResponseLevel::LOCKDOWN) {
                logger_.log(LogLevel::ERROR,
                            "RESPONSE: LOCKDOWN - " + device_id + " (score " +
                                std::to_string(assessment.score) + ")");
                relay_.block(device_id);
                state_machine_.transition(DeviceState::LOCKDOWN);
                responses_[device_id] = ResponseLevel::LOCKDOWN;
            }
            return;
    }
}