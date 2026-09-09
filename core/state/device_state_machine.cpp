// core/state/device_state_machine.cpp
#include "device_state_machine.h"
#include <utility>

DeviceStateMachine::DeviceStateMachine(ILogger* logger) : logger_(logger) {}

const char* DeviceStateMachine::name(DeviceState s) {
    switch (s) {
        case DeviceState::DISCONNECTED:   return "DISCONNECTED";
        case DeviceState::IDENTIFIED:     return "IDENTIFIED";
        case DeviceState::AUTHENTICATING: return "AUTHENTICATING";
        case DeviceState::AUTHENTICATED:  return "AUTHENTICATED";
        case DeviceState::TRUSTED:        return "TRUSTED";
        case DeviceState::NON_TRUSTED:    return "NON_TRUSTED";
        case DeviceState::AUTHORIZED:     return "AUTHORIZED";
        case DeviceState::QUARANTINED:    return "QUARANTINED";
        case DeviceState::REVOKED:        return "REVOKED";
        case DeviceState::LOCKDOWN:       return "LOCKDOWN";
    }
    return "?";
}

bool DeviceStateMachine::transition(DeviceState to) {
    if (to == state_) {
        return false;
    }

    // Allowed transitions per the ARCHITECTURE.md section 11 diagram.
    static const std::pair<DeviceState, DeviceState> allowed[] = {
        // Discovery / identity
        {DeviceState::DISCONNECTED, DeviceState::IDENTIFIED},
        // Phase 1 forward path
        {DeviceState::IDENTIFIED, DeviceState::AUTHENTICATING},
        {DeviceState::AUTHENTICATING, DeviceState::AUTHENTICATED},
        {DeviceState::AUTHENTICATED, DeviceState::TRUSTED},
        {DeviceState::TRUSTED, DeviceState::AUTHORIZED},
        // Phase 1 failure / unknown device -> quarantined
        {DeviceState::IDENTIFIED, DeviceState::QUARANTINED},
        {DeviceState::AUTHENTICATING, DeviceState::QUARANTINED},
        {DeviceState::AUTHENTICATED, DeviceState::QUARANTINED},
        {DeviceState::TRUSTED, DeviceState::QUARANTINED},
        {DeviceState::NON_TRUSTED, DeviceState::QUARANTINED},
        // Phase 2: threat detected on an authorized device
        {DeviceState::AUTHORIZED, DeviceState::QUARANTINED},
        {DeviceState::AUTHORIZED, DeviceState::LOCKDOWN},
        {DeviceState::AUTHORIZED, DeviceState::REVOKED},
        // Escalation: a quarantined device that turns CRITICAL is locked down
        {DeviceState::QUARANTINED, DeviceState::LOCKDOWN},
        // Admin / credential compromise
        {DeviceState::QUARANTINED, DeviceState::REVOKED},
        {DeviceState::QUARANTINED, DeviceState::DISCONNECTED},
    };

    bool valid = false;
    for (const auto& [from, toState] : allowed) {
        if (from == state_ && toState == to) {
            valid = true;
            break;
        }
    }

    if (!valid) {
        if (logger_) {
            logger_->log(LogLevel::WARNING,
                         std::string("state machine: invalid transition ") +
                             name(state_) + " -> " + name(to));
        }
        return false;
    }

    DeviceState from = state_;
    state_ = to;
    if (logger_) {
        logger_->log(LogLevel::INFO,
                     std::string("state machine: ") + name(from) + " -> " + name(to));
    }
    return true;
}