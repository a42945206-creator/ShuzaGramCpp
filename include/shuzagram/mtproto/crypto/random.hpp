#pragma once

#include <cstdint>
#include <functional>
#include <vector>

namespace shuzagram::mtproto::crypto {

// Fills len bytes at buf. Production code uses SystemRandomFill (OpenSSL's
// CSPRNG); tests can substitute a deterministic fill (e.g. all-zero) to
// reproduce a fixed expected output, exactly like gotd/td's
// testutil.ZeroRand{} does for TestRSAPad.
using RandomFill = std::function<void(std::uint8_t* buf, std::size_t len)>;

// Fills `len` random bytes using OpenSSL's CSPRNG (RAND_bytes). Throws
// std::runtime_error on failure.
std::vector<std::uint8_t> SystemRandomBytes(std::size_t len);

// The default RandomFill for production use.
void SystemRandomFill(std::uint8_t* buf, std::size_t len);

} // namespace shuzagram::mtproto::crypto
