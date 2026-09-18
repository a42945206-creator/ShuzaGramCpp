#include "shuzagram/mtproto/crypto/srp.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "bignum_util.hpp"
#include "shuzagram/mtproto/server_exchange.hpp"

// Ported from internal/app/account/srp.go (server side: SrpMakeChallenge =
// makeSRPChallenge/calcSRPB, SrpCalcM1 = calcSRPM1) and gotd/td's
// crypto/srp package (client side: SrpComputeVerifier = computeXV's v,
// SrpClientProof = SRP.Hash).
namespace shuzagram::mtproto::crypto {

namespace {

using detail::AddMod;
using detail::IsGoodLarge;
using detail::Mul;
using detail::MulMod;
using detail::SubMod;

std::array<std::uint8_t, 32> Sha256(const std::vector<std::uint8_t>& data) {
    std::array<std::uint8_t, 32> out{};
    SHA256(data.data(), data.size(), out.data());
    return out;
}

std::vector<std::uint8_t> Sha256Concat(std::initializer_list<std::reference_wrapper<const std::vector<std::uint8_t>>> parts) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::array<std::uint8_t, 32> out{};
    unsigned int out_len = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    for (const auto& p : parts) {
        if (!ok) break;
        ok = EVP_DigestUpdate(ctx, p.get().data(), p.get().size());
    }
    ok = ok && EVP_DigestFinal_ex(ctx, out.data(), &out_len);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("SHA256 (concat) failed");
    return {out.begin(), out.end()};
}

std::array<std::uint8_t, 32> Xor32(const std::array<std::uint8_t, 32>& a, const std::array<std::uint8_t, 32>& b) {
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    return out;
}

std::vector<std::uint8_t> Pbkdf2HmacSha512(const std::vector<std::uint8_t>& password,
                                            const std::vector<std::uint8_t>& salt, int iterations,
                                            std::size_t key_len) {
    std::vector<std::uint8_t> out(key_len);
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()), static_cast<int>(password.size()),
                            salt.data(), static_cast<int>(salt.size()), iterations, EVP_sha512(),
                            static_cast<int>(key_len), out.data())) {
        throw std::runtime_error("PBKDF2-HMAC-SHA512 failed");
    }
    return out;
}

// SH(data, salt) := H(salt | data | salt)
std::vector<std::uint8_t> SaltHash(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& salt) {
    std::vector<std::uint8_t> buf;
    buf.reserve(salt.size() * 2 + data.size());
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), data.begin(), data.end());
    buf.insert(buf.end(), salt.begin(), salt.end());
    const auto h = Sha256(buf);
    return {h.begin(), h.end()};
}

// PH1(password, salt1, salt2) := SH(SH(password, salt1), salt2)
std::vector<std::uint8_t> Ph1(const std::vector<std::uint8_t>& password, const std::vector<std::uint8_t>& salt1,
                               const std::vector<std::uint8_t>& salt2) {
    return SaltHash(SaltHash(password, salt1), salt2);
}

// PH2(password, salt1, salt2) := SH(pbkdf2(sha512, PH1(...), salt1, 100000), salt2)
std::vector<std::uint8_t> Ph2(const std::vector<std::uint8_t>& password, const std::vector<std::uint8_t>& salt1,
                               const std::vector<std::uint8_t>& salt2) {
    const auto ph1 = Ph1(password, salt1, salt2);
    const auto derived = Pbkdf2HmacSha512(ph1, salt1, 100000, 64);
    return SaltHash(derived, salt2);
}

// g as a minimal big-endian byte string -- kSrpBaseG (3) always fits in one byte.
std::vector<std::uint8_t> GBytes() { return {static_cast<std::uint8_t>(kSrpBaseG)}; }

} // namespace

std::vector<std::uint8_t> SrpBaseP() {
    // The same standard Telegram 2048-bit safe prime the DH handshake
    // uses (mtproto::FixedDhPrime) -- SRP and the DH key exchange
    // genuinely share this constant per the protocol spec, not a
    // coincidence this port introduces.
    return FixedDhPrime();
}

std::vector<std::uint8_t> SrpBaseSalt2() {
    return {0xBE, 0xDE, 0x48, 0x88, 0x8C, 0x0F, 0x42, 0xAC, 0x34, 0xFF, 0xD1, 0xD4, 0x93, 0x5D, 0x8B, 0x21};
}

std::vector<std::uint8_t> SrpPadToHash(const std::vector<std::uint8_t>& in) {
    constexpr std::size_t kSize = 256;
    if (in.size() >= kSize) return {in.end() - kSize, in.end()};
    std::vector<std::uint8_t> out(kSize, 0);
    std::copy(in.begin(), in.end(), out.begin() + static_cast<long>(kSize - in.size()));
    return out;
}

SrpChallenge SrpMakeChallenge(const std::vector<std::uint8_t>& verifier, const RandomFill& rand) {
    const auto p = SrpBaseP();
    if (!IsGoodLarge(verifier, p)) throw std::runtime_error("srp: verifier out of range");

    std::vector<std::uint8_t> b_secret(256);
    rand(b_secret.data(), b_secret.size());

    const auto g_padded = SrpPadToHash(GBytes());
    const auto k = Sha256Concat({std::cref(p), std::cref(g_padded)});
    const auto kv = MulMod(k, verifier, p);
    const auto g_b = detail::ModPow(GBytes(), b_secret, p);
    const auto b_value = AddMod(kv, g_b, p);

    SrpChallenge out;
    out.b_secret = std::move(b_secret);
    out.b = SrpPadToHash(b_value);
    return out;
}

std::vector<std::uint8_t> SrpCalcM1(const std::vector<std::uint8_t>& salt1, const std::vector<std::uint8_t>& verifier,
                                     const std::vector<std::uint8_t>& b_secret, const std::vector<std::uint8_t>& srp_b,
                                     const std::vector<std::uint8_t>& client_a) {
    const auto p = SrpBaseP();
    if (!IsGoodLarge(client_a, p)) throw std::runtime_error("srp: A out of range");
    if (!IsGoodLarge(verifier, p)) throw std::runtime_error("srp: verifier out of range");

    const auto a_padded = SrpPadToHash(client_a);
    const auto b_padded = SrpPadToHash(srp_b);
    const auto u = Sha256Concat({std::cref(a_padded), std::cref(b_padded)});
    if (std::all_of(u.begin(), u.end(), [](std::uint8_t b) { return b == 0; })) {
        throw std::runtime_error("srp: u is zero");
    }

    // S = (A * v^u mod p)^b mod p
    const auto v_pow_u = detail::ModPow(verifier, u, p);
    const auto a_times_v_pow_u = MulMod(client_a, v_pow_u, p);
    const auto s_value = detail::ModPow(a_times_v_pow_u, b_secret, p);
    const auto k_value = Sha256(SrpPadToHash(s_value));

    const auto g_padded = SrpPadToHash(GBytes());
    const auto xor_hpg = Xor32(Sha256(p), Sha256(g_padded));
    const std::vector<std::uint8_t> xor_hpg_vec(xor_hpg.begin(), xor_hpg.end());
    const auto salt1_hash = Sha256(salt1);
    const std::vector<std::uint8_t> salt1_hash_vec(salt1_hash.begin(), salt1_hash.end());
    const auto salt2_hash = Sha256(SrpBaseSalt2());
    const std::vector<std::uint8_t> salt2_hash_vec(salt2_hash.begin(), salt2_hash.end());
    const std::vector<std::uint8_t> k_value_vec(k_value.begin(), k_value.end());

    return Sha256Concat({std::cref(xor_hpg_vec), std::cref(salt1_hash_vec), std::cref(salt2_hash_vec),
                          std::cref(a_padded), std::cref(b_padded), std::cref(k_value_vec)});
}

std::vector<std::uint8_t> SrpComputeVerifier(const std::vector<std::uint8_t>& password,
                                              const std::vector<std::uint8_t>& salt1,
                                              const std::vector<std::uint8_t>& salt2) {
    const auto p = SrpBaseP();
    const auto x = Ph2(password, salt1, salt2);
    return SrpPadToHash(detail::ModPow(GBytes(), x, p));
}

SrpClientAnswer SrpClientProof(const std::vector<std::uint8_t>& password, const std::vector<std::uint8_t>& salt1,
                                const std::vector<std::uint8_t>& salt2, const std::vector<std::uint8_t>& srp_b,
                                const std::vector<std::uint8_t>& random) {
    const auto p = SrpBaseP();
    const auto g_padded = SrpPadToHash(GBytes());

    const auto g_a = SrpPadToHash(detail::ModPow(GBytes(), random, p));
    const auto g_b = SrpPadToHash(srp_b);
    const auto u = Sha256Concat({std::cref(g_a), std::cref(g_b)});

    const auto x = Ph2(password, salt1, salt2);
    const auto v = detail::ModPow(GBytes(), x, p);

    const auto k = Sha256Concat({std::cref(p), std::cref(g_padded)});
    const auto kv = MulMod(k, v, p);
    const auto t = SubMod(srp_b, kv, p);
    const auto exponent = detail::Add(random, Mul(u, x));
    const auto s_a = SrpPadToHash(detail::ModPow(t, exponent, p));
    const auto k_a = Sha256(s_a);
    const std::vector<std::uint8_t> k_a_vec(k_a.begin(), k_a.end());

    const auto xor_hpg = Xor32(Sha256(p), Sha256(g_padded));
    const std::vector<std::uint8_t> xor_hpg_vec(xor_hpg.begin(), xor_hpg.end());
    const auto salt1_hash = Sha256(salt1);
    const std::vector<std::uint8_t> salt1_hash_vec(salt1_hash.begin(), salt1_hash.end());
    const auto salt2_hash = Sha256(salt2);
    const std::vector<std::uint8_t> salt2_hash_vec(salt2_hash.begin(), salt2_hash.end());

    SrpClientAnswer out;
    out.a = g_a;
    out.m1 = Sha256Concat({std::cref(xor_hpg_vec), std::cref(salt1_hash_vec), std::cref(salt2_hash_vec),
                            std::cref(g_a), std::cref(g_b), std::cref(k_a_vec)});
    return out;
}

} // namespace shuzagram::mtproto::crypto
