#pragma once

#include <cstdint>
#include <vector>

// Port of github.com/gotd/ige (encrypt.go/decrypt.go): AES in Infinite
// Garble Extension mode, the block-chaining MTProto itself uses (distinct
// from CBC -- IGE chains against both the previous plaintext AND the
// previous ciphertext block, which is what makes a single-bit ciphertext
// error corrupt every following block instead of just one, the deliberate
// tradeoff MTProto's designers made for tamper-evidence over CBC's
// error-recovery). See https://www.links.org/files/openssl-ige.pdf.
//
// Verified against the two official gotd/ige test vectors (also the
// classic OpenSSL IGE vectors) in tests/mtproto_crypto_test.cpp.
namespace shuzagram::mtproto::crypto {

// key must be 16, 24 or 32 bytes (AES-128/192/256, matching Go's
// aes.NewCipher key-length dispatch). iv must be exactly 2*block_size (32)
// bytes: the first 16 are the initial "previous ciphertext" (c), the last
// 16 the initial "previous plaintext" (m). data length must be a multiple
// of 16.
std::vector<std::uint8_t> IgeEncrypt(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv,
                                      const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> IgeDecrypt(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv,
                                      const std::vector<std::uint8_t>& data);

} // namespace shuzagram::mtproto::crypto
