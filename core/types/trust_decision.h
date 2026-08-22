// core/types/trust_decision.h
#pragma once

#include <string>
#include <chrono>

// Trust level resulting from Phase 1 policy evaluation
enum class TrustLevel {
    UNKNOWN,      // Device identity not yet determined
    NON_TRUSTED,  // Device failed authentication or not enrolled
    TRUSTED       // Device authenticated and policy approved
};

// Trust decision from policy evaluation
// Output of TrustPolicy, input to DeviceStateMachine
struct TrustDecision {
    TrustLevel level;
    std::string reason;              // explanation for the decision
    std::chrono::system_clock::time_point decided_at;
};