// core/types/device_state.h
#pragma once

// Device lifecycle states
// Managed by DeviceStateMachine based on TrustDecision and Phase 2 events
enum class DeviceState {
    DISCONNECTED,    // No recent network presence
    IDENTIFIED,      // Seen on network, has DeviceProfile, may have DeviceIdentity
    AUTHENTICATING,  // Authentication attempt in progress
    AUTHENTICATED,   // Crypto identity verified (needs policy approval)
    TRUSTED,         // Intermediate state
    NON_TRUSTED,     // Intermediate state
    AUTHORIZED,      // Fully trusted and network access granted
    QUARANTINED,     // Restricted/isolated (failed auth, threat, unknown device)
    REVOKED,         // Identity permanently no longer trusted
    LOCKDOWN         // Severe threat, complete isolation
};