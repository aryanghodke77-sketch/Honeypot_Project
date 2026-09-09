// phase1/verification_workflow.cpp
#include "verification_workflow.h"

#include <chrono>

namespace {

// Build a deterministic challenge for the observed device.
// In production the server issues an unpredictable nonce; the simulator
// derives one from observed data so runs are fully reproducible.
std::string build_challenge(const DeviceProfile& observed) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  observed.first_seen.time_since_epoch())
                  .count();
    return observed.mac + "|" + observed.ip + "|" + std::to_string(ms);
}

}  // namespace

VerificationWorkflow::VerificationWorkflow(const EnrollmentRegistry& registry,
                                           IAuthProvider& auth_provider,
                                           const TrustPolicy& policy,
                                           IRelay& relay,
                                           DeviceStateMachine& state_machine,
                                           IChallengeSigner& signer,
                                           ILogger* logger)
    : registry_(registry), auth_provider_(auth_provider), policy_(policy),
      relay_(relay), state_machine_(state_machine), signer_(signer),
      logger_(logger) {}

bool VerificationWorkflow::verify(const DeviceProfile& observed) {
    state_machine_.transition(DeviceState::IDENTIFIED);

    // 1. Enrollment registry lookup: unknown MAC -> immediately QUARANTINED.
    const DeviceIdentity* enrolled = registry_.lookup(observed.mac);
    if (enrolled == nullptr) {
        state_machine_.transition(DeviceState::QUARANTINED);
        if (logger_) {
            logger_->log(LogLevel::WARNING,
                         "verification: " + observed.mac + " unknown - not enrolled, quarantined");
        }
        return false;
    }

    // 2. Challenge-response authentication:
    //    issue challenge -> device signs with its private key -> verify.
    state_machine_.transition(DeviceState::AUTHENTICATING);
    std::string challenge = build_challenge(observed);
    std::string signature = signer_.sign(challenge);
    AuthenticationResult auth =
        auth_provider_.authenticate(observed, enrolled, challenge, signature);
    if (!auth.success) {
        state_machine_.transition(DeviceState::QUARANTINED);
        if (logger_) {
            logger_->log(LogLevel::WARNING,
                         "verification: " + observed.mac + " auth failed (" +
                             auth.failure_reason.value_or("no reason") + "), quarantined");
        }
        return false;
    }
    state_machine_.transition(DeviceState::AUTHENTICATED);

    // 3. Deterministic trust policy decision.
    TrustDecision decision = policy_.evaluate(observed, auth, enrolled);

    // 4. Apply decision: TRUSTED -> AUTHORIZED (grant access), else QUARANTINED.
    if (decision.level == TrustLevel::TRUSTED) {
        state_machine_.transition(DeviceState::TRUSTED);
        state_machine_.transition(DeviceState::AUTHORIZED);
        relay_.allow(enrolled->device_id);
        if (logger_) {
            logger_->log(LogLevel::INFO,
                         "verification: " + observed.mac + " AUTHORIZED (" + decision.reason + ")");
        }
        return true;
    }

    state_machine_.transition(DeviceState::QUARANTINED);
    if (logger_) {
        logger_->log(LogLevel::WARNING,
                     "verification: " + observed.mac + " NOT TRUSTED (" + decision.reason + ")");
    }
    return false;
}