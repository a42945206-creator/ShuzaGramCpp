#pragma once

#include <array>

#include "shuzagram/mtproto/transport/codec.hpp"

// Port of proto/codec/abridged.go.
// https://core.telegram.org/mtproto/mtproto-transports#abridged
namespace shuzagram::mtproto::transport {

inline constexpr std::uint8_t kAbridgedClientStart = 0xEF;

class AbridgedCodec final : public Codec {
public:
    void WriteHeader(const WriteBytes& write) override { write(&kAbridgedClientStart, 1); }

    void ReadHeader(const ReadExact& read) override {
        std::uint8_t b;
        read(&b, 1);
        if (b != kAbridgedClientStart) throw ProtocolHeaderMismatchError();
    }

    static constexpr std::array<std::uint8_t, 4> ObfuscatedTag() {
        return {kAbridgedClientStart, kAbridgedClientStart, kAbridgedClientStart, kAbridgedClientStart};
    }

    void Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) override {
        detail::CheckOutgoingMessage(payload);
        detail::CheckAlign(payload, 4);

        const std::uint32_t words = static_cast<std::uint32_t>(payload.size()) >> 2;
        if (words < 0x7f) {
            const auto b = static_cast<std::uint8_t>(words);
            write(&b, 1);
        } else {
            // Header: a single 0x7f byte, then the word count as 3
            // little-endian bytes.
            const std::uint8_t hdr[4] = {0x7f, static_cast<std::uint8_t>(words), static_cast<std::uint8_t>(words >> 8),
                                          static_cast<std::uint8_t>(words >> 16)};
            write(hdr, 4);
        }
        write(payload.data(), payload.size());
    }

    std::vector<std::uint8_t> Read(const ReadExact& read) override {
        const std::size_t n = ReadLength(read);
        std::vector<std::uint8_t> payload(n);
        read(payload.data(), n);
        detail::CheckProtocolError(payload);
        return payload;
    }

private:
    static std::size_t ReadLength(const ReadExact& read) {
        std::uint8_t first;
        read(&first, 1);
        // The high bit requests a quick ACK on client-to-server packets;
        // not surfaced here, but still must not be mistaken for part of the
        // length (quick-ack support is a deliberately deferred piece, see
        // NOTES/transport-framing-plan.md).
        std::uint32_t words = static_cast<std::uint32_t>(first & 0x7f);
        if (words == 0) throw InvalidMessageLengthError(0);
        if (words < 0x7f) {
            const std::size_t n = static_cast<std::size_t>(words) * 4;
            detail::CheckMessageLength(n);
            return n;
        }
        std::uint8_t ext[3];
        read(ext, 3);
        words = static_cast<std::uint32_t>(ext[0]) | (static_cast<std::uint32_t>(ext[1]) << 8) |
                (static_cast<std::uint32_t>(ext[2]) << 16);
        const std::size_t n = static_cast<std::size_t>(words) * 4;
        if (words < 0x7f) throw InvalidMessageLengthError(static_cast<long long>(n));
        detail::CheckMessageLength(n);
        return n;
    }
};

} // namespace shuzagram::mtproto::transport
