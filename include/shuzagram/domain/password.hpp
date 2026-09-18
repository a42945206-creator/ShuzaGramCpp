#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Faithful port of the pieces of internal/domain (PasswordSettings/
// PasswordKDFAlgo) and the account.checkPassword request shape this
// project's narrow 2FA slice needs. See NOTES/auth-check-password-plan.md
// for what's deliberately not carried here: login-email fields, secure
// (Passport) KDF settings, pending-reset-date -- none of those are read or
// written by GetPassword/CheckPassword.
namespace shuzagram::domain {

// One PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
// (the only KDF variant this server, like the Go source, ever uses --
// there is no algo negotiation).
struct PasswordAlgo {
    std::vector<std::uint8_t> salt1;
    std::vector<std::uint8_t> salt2;
    int g = 0;
    std::vector<std::uint8_t> p;
};

struct PasswordSettings {
    bool has_recovery = false;
    bool has_secure_values = false;
    bool has_password = false;
    std::string hint;
    std::vector<std::uint8_t> secure_random;
    PasswordAlgo new_algo;
    // Set only when has_password is true -- the algo the CURRENT verifier
    // was actually computed with.
    std::optional<PasswordAlgo> current_algo;
    std::int64_t srp_id = 0;
    std::vector<std::uint8_t> srp_verifier;  // server-only, never sent to a client
    std::vector<std::uint8_t> srp_b_secret;  // server-only ephemeral secret, never sent to a client
    std::vector<std::uint8_t> srp_b;         // sent to the client as srp_B
};

// domain.PasswordCheck -- the decoded InputCheckPasswordSRP/
// InputCheckPasswordEmpty request payload.
struct PasswordCheck {
    bool empty = false; // true for inputCheckPasswordEmpty
    std::int64_t srp_id = 0;
    std::vector<std::uint8_t> a;
    std::vector<std::uint8_t> m1;
};

} // namespace shuzagram::domain
