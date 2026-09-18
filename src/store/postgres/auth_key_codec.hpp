#pragma once

#include <array>
#include <cstdint>
#include <cstring>

// auth_key_id is stored as a little-endian-interpreted BIGINT (MTProto
// defines it as the low 64 bits of a SHA1 digest, an opaque byte string; the
// Go source's authKeyIDToInt64/authKeyIDFromInt64 in authkey.go pick a fixed
// byte order at the store boundary, and this must match it exactly since
// existing rows in the live database were written that way).
namespace shuzagram::store::postgres::detail {

inline std::int64_t AuthKeyIDToInt64(const std::array<std::uint8_t, 8>& id) {
    std::uint64_t v;
    std::memcpy(&v, id.data(), 8);
#if !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "AuthKeyIDToInt64 assumes a little-endian host"
#endif
    return static_cast<std::int64_t>(v);
}

inline std::array<std::uint8_t, 8> AuthKeyIDFromInt64(std::int64_t v) {
    std::array<std::uint8_t, 8> id{};
    const auto uv = static_cast<std::uint64_t>(v);
    std::memcpy(id.data(), &uv, 8);
    return id;
}

} // namespace shuzagram::store::postgres::detail
