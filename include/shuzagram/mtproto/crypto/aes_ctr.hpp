#pragma once

#include <cstdint>
#include <vector>

// AES-256-CTR as a running keystream -- matches Go's crypto/cipher.Stream
// semantics (crypto/aes.NewCipher + cipher.NewCTR): XorKeyStream can be
// called repeatedly, and the internal keystream position keeps advancing
// across calls, picking up exactly where the previous call left off (even
// mid-block, if a call's length isn't a multiple of 16). Needed because
// obfuscated2 (transport/obfuscated2.hpp) derives one keystream per
// direction and interleaves XorKeyStream calls with the variable-length
// reads/writes of a live connection, not one fixed-size buffer.
namespace shuzagram::mtproto::crypto {

class Aes256CtrStream {
public:
    // key must be exactly 32 bytes, iv (the initial counter block) exactly
    // 16 bytes -- matches Go's aes.NewCipher(32-byte key) + cipher.NewCTR(block, 16-byte iv).
    Aes256CtrStream(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv);
    ~Aes256CtrStream();
    Aes256CtrStream(Aes256CtrStream&& other) noexcept;
    Aes256CtrStream& operator=(Aes256CtrStream&& other) noexcept;
    Aes256CtrStream(const Aes256CtrStream&) = delete;
    Aes256CtrStream& operator=(const Aes256CtrStream&) = delete;

    // dst and src may point at the same buffer (in-place), matching Go's
    // typical XORKeyStream(b, b) usage.
    void XorKeyStream(std::uint8_t* dst, const std::uint8_t* src, std::size_t len);

private:
    struct Impl;
    Impl* impl_;
};

} // namespace shuzagram::mtproto::crypto
