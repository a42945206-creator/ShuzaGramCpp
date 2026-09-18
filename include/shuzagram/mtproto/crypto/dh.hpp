#pragma once

#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// Port of gotd/td's crypto/check_gp.go, check_dh.go, temp_keys.go, salt.go,
// crypto/exchange.go's NonceHash1, and data_with_hash.go -- the
// Diffie-Hellman validation and key-derivation primitives the server-side
// handshake (RunServerHandshake, next piece) is built from.
namespace shuzagram::mtproto::crypto {

// base^exponent mod modulus, as a minimal big-endian byte string (matching
// Go's (*big.Int).Bytes() -- no leading zero padding). The one general-
// purpose modular exponentiation this project needs: computing g_a, g_b and
// the final auth_key = peer_g^my_secret mod dh_prime are all just this.
std::vector<std::uint8_t> ModPow(const std::vector<std::uint8_t>& base, const std::vector<std::uint8_t>& exponent,
                                  const std::vector<std::uint8_t>& modulus);

// g must be one of {2,3,4,5,6,7}, and must generate a cyclic subgroup of
// prime order (p-1)/2 mod p (a quadratic residue). Throws
// std::invalid_argument on an unsupported g, std::runtime_error if g is not
// a quadratic residue mod p. See
// https://core.telegram.org/mtproto/auth_key and
// https://core.telegram.org/api/srp.
void CheckGP(int g, const std::vector<std::uint8_t>& p);

// Checks 1 < g, g_a, g_b < dh_prime - 1, and additionally that g_a, g_b sit
// in the recommended safety range 2^(2048-64) < x < dh_prime - 2^(2048-64).
// Throws std::runtime_error on any violation.
// https://core.telegram.org/mtproto/auth_key#dh-key-exchange-complete
void CheckDHParams(const std::vector<std::uint8_t>& dh_prime, int g, const std::vector<std::uint8_t>& g_a,
                    const std::vector<std::uint8_t>& g_b);

// tmp_aes_key / tmp_aes_iv used to encrypt Server_DH_Params and
// Set_client_DH_params, derived from new_nonce (32 bytes) and server_nonce
// (16 bytes). Operates directly on the raw wire bytes: the Go source routes
// this through *big.Int (TempAESKeys(newNonce, serverNonce *big.Int)), but
// SetBytes+FillBytes on fixed-size input is a lossless round-trip, so the
// intermediate BIGNUM step is skipped here -- see NOTES/transport-handshake-plan.md.
void TempAesKeys(const Int256& new_nonce, const Int128& server_nonce, std::vector<std::uint8_t>& key,
                  std::vector<std::uint8_t>& iv);

// server_salt = substr(new_nonce, 0, 8) XOR substr(server_nonce, 0, 8), read
// little-endian.
std::int64_t ServerSalt(const Int256& new_nonce, const Int128& server_nonce);

// new_nonce_hash1, the DH-completion proof: SHA1(new_nonce + 0x01 +
// SHA1(auth_key)[0:8])[4:20].
Int128 NonceHash1(const Int256& new_nonce, const std::array<std::uint8_t, 256>& auth_key);

// data_with_hash := SHA1(data) + data + (0..15 random bytes), padded to a
// multiple of 16 bytes.
std::vector<std::uint8_t> DataWithHash(const std::vector<std::uint8_t>& data, const RandomFill& rand = SystemRandomFill);

// Recovers data from data_with_hash by trying every possible padding
// length (0..15) and checking which one's SHA1 matches the stored hash.
// Returns an empty optional-like signal (throws std::runtime_error) if none
// matches -- the same "guess" gotd/td's GuessDataWithHash performs, used
// when decrypting a peer-produced Server_DH_Params/Set_client_DH_params
// payload whose padding length isn't otherwise known.
std::vector<std::uint8_t> GuessDataWithHash(const std::vector<std::uint8_t>& data_with_hash);

} // namespace shuzagram::mtproto::crypto
