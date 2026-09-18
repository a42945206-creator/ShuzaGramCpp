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

} // namespace shuzagram::mtproto::crypto::detail
