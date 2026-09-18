#pragma once

#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/random.hpp"

// Port of MTProto's 2FA SRP protocol: internal/app/account/srp.go (server
// side) plus gotd/td's crypto/srp package (client side -- needed only so
// tests can construct a realistic proof without a real client; same role
// as mtproto::crypto::EncryptBindMessage for auth.bindTempAuthKey).
// https://core.telegram.org/api/srp
namespace shuzagram::mtproto::crypto {

// The single (P, g) pair every account on this server uses -- hardcoded
// exactly like the Go source's baseP/baseG constants (no per-account or
// per-request negotiation of a different modulus/generator).
std::vector<std::uint8_t> SrpBaseP(); // 256 bytes, the standard Telegram 2048-bit safe prime
inline constexpr int kSrpBaseG = 3;
std::vector<std::uint8_t> SrpBaseSalt2(); // 16 bytes, fixed -- see SrpCalcM1's own note on why

// Left-pads with zeros to exactly 256 bytes, or -- if longer -- keeps only
// the LAST 256 bytes. Every value mixed into an SRP hash goes through this
// first. Mirrors gotd/td's pad256 / the Go server's padToHash byte-for-byte.
std::vector<std::uint8_t> SrpPadToHash(const std::vector<std::uint8_t>& in);

struct SrpChallenge {
    std::vector<std::uint8_t> b_secret; // 256 raw random bytes (server-only, persisted, never sent to the client)
    std::vector<std::uint8_t> b;        // padded to 256 bytes -- this IS srp_B, sent to the client
};

// Computes a fresh ephemeral (b, B) pair for a persisted verifier v --
// called every time account.getPassword is served for an account that has
// a password (the Go source re-rolls this on every call, never caching
// across requests -- see NOTES/auth-check-password-plan.md). Throws
// std::runtime_error if v is not in the open range (0, P).
SrpChallenge SrpMakeChallenge(const std::vector<std::uint8_t>& verifier, const RandomFill& rand = SystemRandomFill);

// Computes the server's expected M1 for one auth.checkPassword attempt,
// given the account's current salt1, its persisted verifier/b_secret/B
// (from the most recent SrpMakeChallenge), and the client's public A.
// salt2 is deliberately NOT a parameter: the Go source's calcSRPM1 always
// mixes in the hardcoded SrpBaseSalt2() regardless of what's actually
// stored per-account -- harmless in practice since every account's stored
// salt2 is required to equal it anyway (see the "new password" validation
// this project doesn't otherwise port), but ported here exactly as the
// upstream behavior, not "corrected" to read the stored value.
//
// Throws std::runtime_error if A or the verifier are out of the open range
// (0, P), or if u = H(pad(A), pad(B)) is zero -- callers should map any of
// these to PASSWORD_HASH_INVALID, matching the Go source's blanket
// ErrPasswordHashInvalid for every one of these cases (never distinguish
// them in a public error to an unauthenticated-for-this-check caller).
std::vector<std::uint8_t> SrpCalcM1(const std::vector<std::uint8_t>& salt1, const std::vector<std::uint8_t>& verifier,
                                     const std::vector<std::uint8_t>& b_secret, const std::vector<std::uint8_t>& srp_b,
                                     const std::vector<std::uint8_t>& client_a);

// ---- Client-side (test-only helpers; the server itself never calls these) ----

// x = PH2(password, salt1, salt2); v = g^x mod P, padded to 256 bytes.
// What a client computes once to prove knowledge of a password (via
// SrpClientProof below) or to set a NEW one (account.updatePasswordSettings
// -- not otherwise ported by this project).
std::vector<std::uint8_t> SrpComputeVerifier(const std::vector<std::uint8_t>& password,
                                              const std::vector<std::uint8_t>& salt1,
                                              const std::vector<std::uint8_t>& salt2);

struct SrpClientAnswer {
    std::vector<std::uint8_t> a;  // g_a, padded to 256 bytes
    std::vector<std::uint8_t> m1; // 32 bytes
};

// A full client-side auth.checkPassword proof computation, given the
// server's current salt1/salt2/srp_B (from account.getPassword) and the
// client's own secret exponent `random` (a genuine client draws this from
// a CSPRNG; tests pass a fixed value for reproducibility, exactly like
// gotd/td's own TestSRP does). Unlike SrpCalcM1, this takes salt2
// explicitly: a real client has no reason to assume it equals any
// particular constant, it just uses whatever the server sent. Mirrors
// gotd/td's crypto/srp.SRP.Hash byte-for-byte -- verified against its own
// official test vector in tests/mtproto_srp_test.cpp.
SrpClientAnswer SrpClientProof(const std::vector<std::uint8_t>& password, const std::vector<std::uint8_t>& salt1,
                                const std::vector<std::uint8_t>& salt2, const std::vector<std::uint8_t>& srp_b,
                                const std::vector<std::uint8_t>& random);

} // namespace shuzagram::mtproto::crypto
