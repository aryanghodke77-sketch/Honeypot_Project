// tests/unit/crypto_validation.cpp
// Unit tests for the simulated crypto layer:
//   - SHA-256 / HMAC-SHA256 against known test vectors (NIST / RFC 4231)
//   - SimulatedDevice signing determinism
//   - SimulatedAuthProvider challenge-response success/failure cases
#include <iostream>
#include <string>

#include "core/crypto/sha256.h"
#include "simulation/simulated_auth_provider.h"
#include "simulation/simulated_device.h"

using namespace std;

int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            cout << "  ok: " #cond "\n";                                     \
        } else {                                                             \
            cout << "  FAIL: " #cond "\n";                                   \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

int main() {
    cout << "Crypto validation\n=================\n\n";

    cout << "-- SHA-256 known vectors --\n";
    CHECK(crypto::sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(crypto::sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(crypto::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    cout << "-- HMAC-SHA256 known vectors --\n";
    CHECK(crypto::hmac_sha256_hex("key", "The quick brown fox jumps over the lazy dog") ==
          "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    // RFC 4231 test case 6: key longer than one block (131 x 0xaa)
    CHECK(crypto::hmac_sha256_hex(string(131, '\xaa'),
                                  "Test Using Larger Than Block-Size Key - Hash Key First") ==
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    cout << "-- SimulatedDevice signing --\n";
    {
        SimulatedDevice device("simulated-device-secret-001");
        string s1 = device.sign("challenge-1");
        string s2 = device.sign("challenge-1");
        CHECK(!s1.empty() && s1.size() == 64);        // 32-byte digest, hex
        CHECK(s1 == s2);                              // deterministic
        CHECK(s1 != device.sign("challenge-2"));      // challenge matters
    }

    cout << "-- SimulatedAuthProvider challenge-response --\n";
    {
        const string secret = "simulated-device-secret-001";
        SimulatedDevice device(secret);

        DeviceProfile prof;
        prof.mac = "AA:BB:CC:DD:EE:01";
        prof.ip = "192.168.1.101";

        DeviceIdentity enrolled;
        enrolled.device_id = "trusted-laptop-001";
        enrolled.mac = prof.mac;
        enrolled.public_key_jwk = secret;

        SimulatedAuthProvider auth;
        string challenge = "server-issued-nonce";

        // Valid signature from the device with the matching key.
        AuthenticationResult ok =
            auth.authenticate(prof, &enrolled, challenge, device.sign(challenge));
        CHECK(ok.success);
        CHECK(ok.mechanism == "hmac_challenge_response");
        CHECK(ok.signature == device.sign(challenge));  // proof echoed

        // Signature over a different challenge must fail.
        AuthenticationResult replay =
            auth.authenticate(prof, &enrolled, challenge, device.sign("old-challenge"));
        CHECK(!replay.success);
        CHECK(replay.failure_reason == "signature verification failed");

        // Device holding the WRONG key must fail.
        SimulatedDevice impostor("attacker-key");
        AuthenticationResult spoof =
            auth.authenticate(prof, &enrolled, challenge, impostor.sign(challenge));
        CHECK(!spoof.success);

        // Unknown / unenrolled device must fail.
        AuthenticationResult unknown =
            auth.authenticate(prof, nullptr, challenge, device.sign(challenge));
        CHECK(!unknown.success);
        CHECK(unknown.failure_reason == "unknown device - not enrolled");

        // Enrolled but no registered credential must fail.
        DeviceIdentity no_key = enrolled;
        no_key.public_key_jwk.clear();
        AuthenticationResult no_cred =
            auth.authenticate(prof, &no_key, challenge, device.sign(challenge));
        CHECK(!no_cred.success);
        CHECK(no_cred.failure_reason == "no enrolled credential");
    }

    cout << "\n===========================\n";
    if (failures == 0) {
        cout << "All crypto checks PASSED!\n";
        return 0;
    }
    cout << failures << " check(s) FAILED\n";
    return 1;
}