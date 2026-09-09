// core/state/device_state_machine.h
#pragma once

#include <optional>
#include "../types/device_state.h"
#include "../../interfaces/i_logger.h"

// Device lifecycle state machine (ARCHITECTURE.md section 11)
// One instance per device. No other code mutates DeviceState directly -
// all transitions go through here so they stay valid and (optionally) logged.
//
// Phase 1 drives:   IDENTIFIED -> AUTHENTICATING -> AUTHENTICATED -> TRUSTED -> AUTHORIZED
//                   (failure branches -> QUARANTINED)
// Phase 2 drives:   AUTHORIZED -> QUARANTINED | LOCKDOWN  (threat detected)
//                   QUARANTINED/REVOKED are terminal-ish; REVOKED is permanent.
class DeviceStateMachine {
public:
    // Optional logger for transition logging (dependency injection).
    explicit DeviceStateMachine(ILogger* logger = nullptr);

    // Attempt a transition to `to`. Returns true if valid and applied.
    bool transition(DeviceState to);

    DeviceState state() const { return state_; }

    // Human-readable state name (logging/display).
    static const char* name(DeviceState s);

private:
    DeviceState state_ = DeviceState::DISCONNECTED;
    ILogger* logger_;
};