#pragma once

#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/bn.h>

// Shared internal helpers for converting between big-endian byte vectors
// (how every MTProto TL field carrying a large integer is shaped) and
// OpenSSL BIGNUM, used by both the raw-RSA transform (rsa.cpp) and the
// Diffie-Hellman math (dh.cpp, server_exchange.cpp). Not a public header --
// lives under src/, included via relative path.
namespace shuzagram::mtproto::crypto::detail {

using BignumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

inline BignumPtr MakeBignum() { return {BN_new(), &BN_free}; }

inline BignumPtr BytesToBignum(const std::vector<std::uint8_t>& b) {
    BignumPtr bn = MakeBignum();
    if (!BN_bin2bn(b.data(), static_cast<int>(b.size()), bn.get())) {
        throw std::runtime_error("BN_bin2bn failed");
    }
    return bn;
}

// Minimal big-endian encoding, matching Go's (*big.Int).Bytes() -- no
// leading zero padding, and an empty vector for zero.
inline std::vector<std::uint8_t> BignumToMinimalBytes(const BIGNUM* bn) {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    return out;
}

// Fixed-length big-endian encoding (left-padded with zeros), throwing if
// the value doesn't fit -- matches Go's crypto.FillBytes-checked helper.
inline std::vector<std::uint8_t> BignumToFixedBytes(const BIGNUM* bn, std::size_t fixed_len) {
    std::vector<std::uint8_t> out(fixed_len);
    if (BN_num_bytes(bn) > static_cast<int>(fixed_len)) {
        throw std::runtime_error("value does not fit in the requested fixed length");
    }
    if (!BN_bn2binpad(bn, out.data(), static_cast<int>(fixed_len))) {
        throw std::runtime_error("BN_bn2binpad failed");
    }
    return out;
}

// base^exponent mod modulus, as minimal big-endian bytes.
inline std::vector<std::uint8_t> ModPow(const std::vector<std::uint8_t>& base,
                                         const std::vector<std::uint8_t>& exponent,
                                         const std::vector<std::uint8_t>& modulus) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr b = BytesToBignum(base);
    BignumPtr e = BytesToBignum(exponent);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_exp(result.get(), b.get(), e.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_exp failed");
    }
    return BignumToMinimalBytes(result.get());
}

// (a * b) mod modulus, (a + b) mod modulus, (a - b) mod modulus -- all as
// minimal big-endian bytes. Used by the SRP math (srp.cpp), which mixes
// modular add/multiply with modular exponentiation in ways ModPow alone
// doesn't cover. BN_mod_sub already produces a result in [0, modulus),
// even when a < b, so callers don't need Go's manual "add modulus back if
// negative" branch (crypto/account/srp.go does that only because
// math/big.Int.Sub can go negative; OpenSSL's BN_mod_sub never does).
inline std::vector<std::uint8_t> MulMod(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b,
                                         const std::vector<std::uint8_t>& modulus) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr an = BytesToBignum(a);
    BignumPtr bn = BytesToBignum(b);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_mul(result.get(), an.get(), bn.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_mul failed");
    }
    return BignumToMinimalBytes(result.get());
}

inline std::vector<std::uint8_t> AddMod(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b,
                                         const std::vector<std::uint8_t>& modulus) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr an = BytesToBignum(a);
    BignumPtr bn = BytesToBignum(b);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_add(result.get(), an.get(), bn.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_add failed");
    }
    return BignumToMinimalBytes(result.get());
}

inline std::vector<std::uint8_t> SubMod(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b,
                                         const std::vector<std::uint8_t>& modulus) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr an = BytesToBignum(a);
    BignumPtr bn = BytesToBignum(b);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_sub(result.get(), an.get(), bn.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_sub failed");
    }
    return BignumToMinimalBytes(result.get());
}

// Adds two plain (non-modular) non-negative bignums -- the SRP client
// exponent `a + u*x` is a real sum used as a modexp exponent, never
// reduced mod anything itself (BN_mod_exp accepts any nonnegative
// exponent).
inline std::vector<std::uint8_t> Add(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    BignumPtr an = BytesToBignum(a);
    BignumPtr bn = BytesToBignum(b);
    BignumPtr result = MakeBignum();
    if (!BN_add(result.get(), an.get(), bn.get())) throw std::runtime_error("BN_add failed");
    return BignumToMinimalBytes(result.get());
}

inline std::vector<std::uint8_t> Mul(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr an = BytesToBignum(a);
    BignumPtr bn = BytesToBignum(b);
    BignumPtr result = MakeBignum();
    if (!BN_mul(result.get(), an.get(), bn.get(), ctx.get())) throw std::runtime_error("BN_mul failed");
    return BignumToMinimalBytes(result.get());
}

// 0 < n < modulus, matching the Go source's isGoodLarge (a laxer check
// than the SRP spec's "1 < n < p-1" -- ported exactly as-is, not
// "improved", since the server's own validation uses this precise bound).
inline bool IsGoodLarge(const std::vector<std::uint8_t>& n, const std::vector<std::uint8_t>& modulus) {
    BignumPtr nn = BytesToBignum(n);
    BignumPtr mm = BytesToBignum(modulus);
    return !BN_is_zero(nn.get()) && !BN_is_negative(nn.get()) && BN_cmp(nn.get(), mm.get()) < 0;
}

} // namespace shuzagram::mtproto::crypto::detail
