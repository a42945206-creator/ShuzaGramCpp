#include "shuzagram/mtproto/crypto/dh.hpp"

#include <array>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "bignum_util.hpp"
#include "shuzagram/mtproto/crypto/aes_ige.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp" // kRsaKeyBits

namespace shuzagram::mtproto::crypto {

namespace {

using detail::BignumPtr;
using detail::BytesToBignum;
using detail::MakeBignum;

bool CheckSubgroup(const BIGNUM* p, std::uint64_t divider, std::initializer_list<std::uint64_t> expected) {
    const BN_ULONG rem = BN_mod_word(p, divider);
    for (const auto e : expected) {
        if (rem == e) return true;
    }
    return false;
}

// min < x < max (strict), matching Go's crypto.InRange.
bool InRange(const BIGNUM* x, const BIGNUM* lo, const BIGNUM* hi) { return BN_cmp(x, lo) > 0 && BN_cmp(x, hi) < 0; }

std::vector<std::uint8_t> Sha1(const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out(SHA_DIGEST_LENGTH);
    SHA1(data.data(), data.size(), out.data());
    return out;
}

std::vector<std::uint8_t> Sha1(const std::uint8_t* a, std::size_t a_len, const std::uint8_t* b, std::size_t b_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::vector<std::uint8_t> out(SHA_DIGEST_LENGTH);
    unsigned int out_len = 0;
    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) || !EVP_DigestUpdate(ctx, a, a_len) ||
        !EVP_DigestUpdate(ctx, b, b_len) || !EVP_DigestFinal_ex(ctx, out.data(), &out_len)) {
        if (ctx) EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA1 (two-part) failed");
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

std::size_t PaddedLen16(std::size_t l) {
    const std::size_t n = 16 * (l / 16);
    return n < l ? n + 16 : n;
}

} // namespace

std::vector<std::uint8_t> ModPow(const std::vector<std::uint8_t>& base, const std::vector<std::uint8_t>& exponent,
                                  const std::vector<std::uint8_t>& modulus) {
    return detail::ModPow(base, exponent, modulus);
}

std::vector<std::uint8_t> ModPowFixed(const std::vector<std::uint8_t>& base, const std::vector<std::uint8_t>& exponent,
                                       const std::vector<std::uint8_t>& modulus, std::size_t fixed_len) {
    detail::CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr b = BytesToBignum(base);
    BignumPtr e = BytesToBignum(exponent);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_exp(result.get(), b.get(), e.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_exp failed");
    }
    return detail::BignumToFixedBytes(result.get(), fixed_len);
}

void CheckGP(int g, const std::vector<std::uint8_t>& p) {
    BignumPtr bn_p = BytesToBignum(p);
    bool ok;
    switch (g) {
        case 2: ok = CheckSubgroup(bn_p.get(), 8, {7}); break;
        case 3: ok = CheckSubgroup(bn_p.get(), 3, {2}); break;
        case 4: ok = true; break;
        case 5: ok = CheckSubgroup(bn_p.get(), 5, {1, 4}); break;
        case 6: ok = CheckSubgroup(bn_p.get(), 24, {19, 23}); break;
        case 7: ok = CheckSubgroup(bn_p.get(), 7, {3, 5, 6}); break;
        default: throw std::invalid_argument("CheckGP: g must be 2, 3, 4, 5, 6 or 7");
    }
    if (!ok) throw std::runtime_error("CheckGP: g is not a quadratic residue mod p");
}

void CheckDHParams(const std::vector<std::uint8_t>& dh_prime, int g, const std::vector<std::uint8_t>& g_a,
                    const std::vector<std::uint8_t>& g_b) {
    BignumPtr p = BytesToBignum(dh_prime);
    BignumPtr ga = BytesToBignum(g_a);
    BignumPtr gb = BytesToBignum(g_b);
    BignumPtr one = MakeBignum();
    BN_one(one.get());
    BignumPtr p_minus_one = MakeBignum();
    BN_sub(p_minus_one.get(), p.get(), one.get());

    BignumPtr g_bn = MakeBignum();
    BN_set_word(g_bn.get(), static_cast<BN_ULONG>(g));
    if (!InRange(g_bn.get(), one.get(), p_minus_one.get())) {
        throw std::runtime_error("CheckDHParams: bad g, g must be 1 < g < dh_prime - 1");
    }
    if (!InRange(ga.get(), one.get(), p_minus_one.get())) {
        throw std::runtime_error("CheckDHParams: bad g_a, g_a must be 1 < g_a < dh_prime - 1");
    }
    if (!InRange(gb.get(), one.get(), p_minus_one.get())) {
        throw std::runtime_error("CheckDHParams: bad g_b, g_b must be 1 < g_b < dh_prime - 1");
    }

    // Recommended additional range: 2^{2048-64} < g_a, g_b < dh_prime - 2^{2048-64}.
    BignumPtr safety_min = MakeBignum();
    BN_set_word(safety_min.get(), 1);
    BN_lshift(safety_min.get(), safety_min.get(), kRsaKeyBits - 64);
    BignumPtr safety_max = MakeBignum();
    BN_sub(safety_max.get(), p.get(), safety_min.get());

    if (!InRange(ga.get(), safety_min.get(), safety_max.get())) {
        throw std::runtime_error("CheckDHParams: bad g_a, out of the recommended safety range");
    }
    if (!InRange(gb.get(), safety_min.get(), safety_max.get())) {
        throw std::runtime_error("CheckDHParams: bad g_b, out of the recommended safety range");
    }
}

void TempAesKeys(const Int256& new_nonce, const Int128& server_nonce, std::vector<std::uint8_t>& key,
                  std::vector<std::uint8_t>& iv) {
    const auto nn_sn = Sha1(new_nonce.data(), new_nonce.size(), server_nonce.data(), server_nonce.size());
    const auto sn_nn = Sha1(server_nonce.data(), server_nonce.size(), new_nonce.data(), new_nonce.size());
    const auto nn_nn = Sha1(new_nonce.data(), new_nonce.size(), new_nonce.data(), new_nonce.size());

    // tmp_aes_key := SHA1(new_nonce+server_nonce) + substr(SHA1(server_nonce+new_nonce), 0, 12)
    key.assign(nn_sn.begin(), nn_sn.end());
    key.insert(key.end(), sn_nn.begin(), sn_nn.begin() + 12);

    // tmp_aes_iv := substr(SHA1(server_nonce+new_nonce), 12, 8) + SHA1(new_nonce+new_nonce) + substr(new_nonce, 0, 4)
    iv.assign(sn_nn.begin() + 12, sn_nn.begin() + 20);
    iv.insert(iv.end(), nn_nn.begin(), nn_nn.end());
    iv.insert(iv.end(), new_nonce.begin(), new_nonce.begin() + 4);
}

std::int64_t ServerSalt(const Int256& new_nonce, const Int128& server_nonce) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(new_nonce[static_cast<std::size_t>(i)] ^
                                                                    server_nonce[static_cast<std::size_t>(i)]))
             << (8 * i);
    }
    return static_cast<std::int64_t>(v);
}

Int128 NonceHash1(const Int256& new_nonce, const std::array<std::uint8_t, 256>& auth_key) {
    const auto key_hash = Sha1(std::vector<std::uint8_t>(auth_key.begin(), auth_key.end()));

    std::vector<std::uint8_t> buf(new_nonce.begin(), new_nonce.end());
    buf.push_back(0x01);
    buf.insert(buf.end(), key_hash.begin(), key_hash.begin() + 8);

    const auto digest = Sha1(buf);
    Int128 out{};
    std::copy(digest.begin() + 4, digest.begin() + 20, out.begin());
    return out;
}

std::vector<std::uint8_t> DataWithHash(const std::vector<std::uint8_t>& data, const RandomFill& rand) {
    std::vector<std::uint8_t> out(PaddedLen16(data.size() + SHA_DIGEST_LENGTH));
    const auto hash = Sha1(data);
    std::copy(hash.begin(), hash.end(), out.begin());
    std::copy(data.begin(), data.end(), out.begin() + SHA_DIGEST_LENGTH);
    const std::size_t pad_start = SHA_DIGEST_LENGTH + data.size();
    if (pad_start < out.size()) rand(out.data() + pad_start, out.size() - pad_start);
    return out;
}

std::vector<std::uint8_t> GuessDataWithHash(const std::vector<std::uint8_t>& data_with_hash) {
    if (data_with_hash.size() <= SHA_DIGEST_LENGTH) {
        throw std::runtime_error("GuessDataWithHash: input too small");
    }
    const std::vector<std::uint8_t> want(data_with_hash.begin(), data_with_hash.begin() + SHA_DIGEST_LENGTH);
    for (int i = 0; i < 16; ++i) {
        if (static_cast<int>(data_with_hash.size()) - i < SHA_DIGEST_LENGTH) break;
        const std::vector<std::uint8_t> candidate(data_with_hash.begin() + SHA_DIGEST_LENGTH,
                                                    data_with_hash.end() - i);
        if (Sha1(candidate) == want) return candidate;
    }
    throw std::runtime_error("GuessDataWithHash: no padding length matched the stored hash");
}

std::vector<std::uint8_t> EncryptExchangeAnswer(const std::vector<std::uint8_t>& answer,
                                                 const std::vector<std::uint8_t>& key,
                                                 const std::vector<std::uint8_t>& iv, const RandomFill& rand) {
    return IgeEncrypt(key, iv, DataWithHash(answer, rand));
}

std::vector<std::uint8_t> DecryptExchangeAnswer(const std::vector<std::uint8_t>& data,
                                                 const std::vector<std::uint8_t>& key,
                                                 const std::vector<std::uint8_t>& iv) {
    return GuessDataWithHash(IgeDecrypt(key, iv, data));
}

} // namespace shuzagram::mtproto::crypto
