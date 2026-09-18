#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Self-contained CRC-32/ISO-HDLC ("CRC32 IEEE"), the same algorithm as
// zlib's crc32() and Go's hash/crc32.IEEETable -- what proto/codec/full.go
// uses. Table-based, standard reflected polynomial 0xEDB88320. Not part of
// the public API: only the Full transport codec needs it.
namespace shuzagram::mtproto::transport::detail {

inline const std::array<std::uint32_t, 256>& Crc32Table() {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    return table;
}

inline std::uint32_t Crc32Ieee(const std::uint8_t* data, std::size_t len) {
    const auto& table = Crc32Table();
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

} // namespace shuzagram::mtproto::transport::detail
