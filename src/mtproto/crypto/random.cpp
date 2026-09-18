#include "shuzagram/mtproto/crypto/random.hpp"

#include <stdexcept>

#include <openssl/rand.h>

namespace shuzagram::mtproto::crypto {

void SystemRandomFill(std::uint8_t* buf, std::size_t len) {
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) throw std::runtime_error("RAND_bytes failed");
}

std::vector<std::uint8_t> SystemRandomBytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);
    SystemRandomFill(out.data(), len);
    return out;
}

} // namespace shuzagram::mtproto::crypto
