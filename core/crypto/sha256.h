// core/crypto/sha256.h
#pragma once

#include <string>

// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
// Pure, dependency-free C++17 - usable by both the simulated device signer
// and the auth provider verifier. Real cryptography; the KEYS are simulated
// strings until real hardware/secure-element integration.
namespace crypto {

// SHA-256 digest of `data`, lowercase hex (64 chars).
std::string sha256_hex(const std::string& data);

// HMAC-SHA256 of `data` keyed by `key`, lowercase hex (64 chars).
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

}  // namespace crypto