// core/types/authentication_result.h
#pragma once

#include <string>
#include <optional>

// Result of an authentication attempt
// Returned by IAuthProvider::authenticate()
// Communicates success/failure and mechanism used
struct AuthenticationResult {
    bool success;                    // whether auth succeeded
    std::string mechanism;           // "certificate" | "mac_allowlist" | "manual"
    std::optional<std::string> signature;    // challenge-response proof if applicable
    std::optional<std::string> failure_reason; // explanation if failed
};