// phase1/verification_workflow.h
#pragma once

#include <string>
#include "../core/identity/enrollment_registry.h"
#include "../core/policy/trust_policy.h"
#include "../core/state/device_state_machine.h"
#include "../interfaces/i_auth_provider.h"
#include "../interfaces/i_challenge_signer.h"
#include "../interfaces/i_relay.h"
#include "../interfaces/i_logger.h"

// Phase 1 driver (ARCHITECTURE.md section 7):
//   DeviceProfile -> registry lookup -> challenge-response authentication
//   -> policy -> state machine -> AUTHORIZED (relay.allow) or QUARANTINED.
// All collaborators are injected; this code never constructs a simulator or
// hardware object and has no knowledge of where packets came from.
class VerificationWorkflow {
public:
    VerificationWorkflow(const EnrollmentRegistry& registry,
                         IAuthProvider& auth_provider,
                         const TrustPolicy& policy,
                         IRelay& relay,
                         DeviceStateMachine& state_machine,
                         IChallengeSigner& signer,
                         ILogger* logger = nullptr);

    // Run the verification chain for an observed device.
    // Returns true if the device ended AUTHORIZED.
    bool verify(const DeviceProfile& observed);

private:
    const EnrollmentRegistry& registry_;
    IAuthProvider& auth_provider_;
    const TrustPolicy& policy_;
    IRelay& relay_;
    DeviceStateMachine& state_machine_;
    IChallengeSigner& signer_;
    ILogger* logger_;
};