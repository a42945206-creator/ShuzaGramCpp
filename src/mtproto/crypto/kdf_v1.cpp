#include "shuzagram/mtproto/crypto/kdf_v1.hpp"

#include <openssl/sha.h>

// Ported from gotd/td's crypto/kdf_v1.go (MessageKeyV1) and crypto/keys_old.go
// (sha1a..sha1d, OldKeys -- here specialized to the fixed x=0 schedule
// KeysV1 always uses).
namespace shuzagram::mtproto::crypto {

namespace {

std::array<std::uint8_t, 20> Sha1a(const AuthKeyBytes& auth_key, const Int128& msg_key) {
    // sha1_a = SHA1(msg_key + substr(auth_key, x, 32))
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, msg_key.data(), msg_key.size());
    SHA1_Update(&ctx, auth_key.data(), 32);
    std::array<std::uint8_t, 20> out{};
    SHA1_Final(out.data(), &ctx);
    return out;
}

std::array<std::uint8_t, 20> Sha1b(const AuthKeyBytes& auth_key, const Int128& msg_key) {
    // sha1_b = SHA1(substr(auth_key, 32+x, 16) + msg_key + substr(auth_key, 48+x, 16))
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, auth_key.data() + 32, 16);
    SHA1_Update(&ctx, msg_key.data(), msg_key.size());
    SHA1_Update(&ctx, auth_key.data() + 48, 16);
    std::array<std::uint8_t, 20> out{};
    SHA1_Final(out.data(), &ctx);
    return out;
}

std::array<std::uint8_t, 20> Sha1c(const AuthKeyBytes& auth_key, const Int128& msg_key) {
    // sha1_c = SHA1(substr(auth_key, 64+x, 32) + msg_key)
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, auth_key.data() + 64, 32);
    SHA1_Update(&ctx, msg_key.data(), msg_key.size());
    std::array<std::uint8_t, 20> out{};
    SHA1_Final(out.data(), &ctx);
    return out;
}

std::array<std::uint8_t, 20> Sha1d(const AuthKeyBytes& auth_key, const Int128& msg_key) {
    // sha1_d = SHA1(msg_key + substr(auth_key, 96+x, 32))
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, msg_key.data(), msg_key.size());
    SHA1_Update(&ctx, auth_key.data() + 96, 32);
    std::array<std::uint8_t, 20> out{};
    SHA1_Final(out.data(), &ctx);
    return out;
}

} // namespace

Int128 MessageKeyV1(const std::vector<std::uint8_t>& plaintext) {
    std::array<std::uint8_t, 20> sum{};
    SHA1(plaintext.data(), plaintext.size(), sum.data());
    Int128 out{};
    std::copy(sum.begin() + 4, sum.begin() + 20, out.begin());
    return out;
}

void KeysV1(const AuthKeyBytes& auth_key, const Int128& msg_key, std::vector<std::uint8_t>& key,
            std::vector<std::uint8_t>& iv) {
    const auto a = Sha1a(auth_key, msg_key);
    const auto b = Sha1b(auth_key, msg_key);
    const auto c = Sha1c(auth_key, msg_key);
    const auto d = Sha1d(auth_key, msg_key);

    // aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
    key.clear();
    key.insert(key.end(), a.begin(), a.begin() + 8);
    key.insert(key.end(), b.begin() + 8, b.begin() + 20);
    key.insert(key.end(), c.begin() + 4, c.begin() + 16);

    // aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]
    iv.clear();
    iv.insert(iv.end(), a.begin() + 8, a.begin() + 20);
    iv.insert(iv.end(), b.begin(), b.begin() + 8);
    iv.insert(iv.end(), c.begin() + 16, c.begin() + 20);
    iv.insert(iv.end(), d.begin(), d.begin() + 8);
}

} // namespace shuzagram::mtproto::crypto
