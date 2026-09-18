#pragma once

#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"

// Port of crypto/rsa_pad.go (gotd/td): MTProto's own RSA padding scheme
// ("presenting proof of work / server authentication"), used to encrypt
// req_DH_params.encrypted_data and decrypt it server-side. Not PKCS#1/OAEP.
// See https://core.telegram.org/mtproto/auth_key#presenting-proof-of-work-server-authentication.
namespace shuzagram::mtproto::crypto {

inline constexpr std::size_t kRsaPadDataLimit = 144;

// Encrypts data (must be <= 144 bytes) to key. Retries internally (drawing
// fresh randomness each time via `rand`) until the intermediate value lands
// below the RSA modulus, per the spec. Result is always exactly
// kRsaByteLen (256) bytes.
std::vector<std::uint8_t> RsaPad(const std::vector<std::uint8_t>& data, const RsaPublicKey& key,
                                  const RandomFill& rand = SystemRandomFill);

// Server-side decode: reverses RsaPad. Returns the 192-byte
// data_with_padding (caller's TL payload occupies the front of it, the rest
// is random filler -- exactly like Go's DecodeRSAPad, which does not trim
// it). Throws std::runtime_error if the hash check fails (wrong key or
// corrupted data).
std::vector<std::uint8_t> RsaUnpad(const std::vector<std::uint8_t>& data, const RsaPrivateKey& key);

} // namespace shuzagram::mtproto::crypto
