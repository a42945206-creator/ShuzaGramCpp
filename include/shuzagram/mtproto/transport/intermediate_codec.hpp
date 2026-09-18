#pragma once

#include <array>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/transport/codec.hpp"

// Port of proto/codec/intermediate.go and padded_intermediate.go, which
// share the same frame shape (a 4-byte little-endian length prefix, then
// the payload) and differ only in whether the sender appends 0-3 random
// trailing bytes and the header marker.
// https://core.telegram.org/mtproto/mtproto-transports#intermediate
// https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate
namespace shuzagram::mtproto::transport {

inline constexpr std::array<std::uint8_t, 4> kIntermediateClientStart = {0xEE, 0xEE, 0xEE, 0xEE};
inline constexpr std::array<std::uint8_t, 4> kPaddedIntermediateClientStart = {0xDD, 0xDD, 0xDD, 0xDD};

namespace detail {

inline void WriteIntermediateFrame(const WriteBytes& write, const std::vector<std::uint8_t>& payload) {
    transport::detail::WriteU32Le(write, static_cast<std::uint32_t>(payload.size()));
    write(payload.data(), payload.size());
}

// padding: when true, the trailing 0-3 bytes beyond the last full 4-byte
// word are trimmed off (padded-intermediate framing); when false, the
// payload length is used exactly as declared (plain intermediate).
inline std::vector<std::uint8_t> ReadIntermediateFrame(const ReadExact& read, bool padding) {
    const std::uint32_t n = transport::detail::ReadU32Le(read);
    transport::detail::CheckMessageLength(n);
    std::vector<std::uint8_t> payload(n);
    read(payload.data(), n);
    if (padding) {
        const std::size_t pad = payload.size() % 4;
        payload.resize(payload.size() - pad);
    }
    return payload;
}

} // namespace detail

class IntermediateCodec final : public Codec {
public:
    void WriteHeader(const WriteBytes& write) override { write(kIntermediateClientStart.data(), 4); }

    void ReadHeader(const ReadExact& read) override {
        std::array<std::uint8_t, 4> got{};
        read(got.data(), 4);
        if (got != kIntermediateClientStart) throw ProtocolHeaderMismatchError();
    }

    void Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) override {
        detail::CheckOutgoingMessage(payload);
        detail::CheckAlign(payload, 4);
        detail::WriteIntermediateFrame(write, payload);
    }

    std::vector<std::uint8_t> Read(const ReadExact& read) override {
        auto payload = detail::ReadIntermediateFrame(read, /*padding=*/false);
        detail::CheckProtocolError(payload);
        return payload;
    }
};

class PaddedIntermediateCodec final : public Codec {
public:
    // rand supplies the 0-3 trailing padding bytes; defaults to the
    // project's system CSPRNG, but is injectable the same way RsaPad's
    // RandomFill is, for deterministic tests.
    explicit PaddedIntermediateCodec(crypto::RandomFill rand = crypto::SystemRandomFill) : rand_(std::move(rand)) {}

    void WriteHeader(const WriteBytes& write) override { write(kPaddedIntermediateClientStart.data(), 4); }

    void ReadHeader(const ReadExact& read) override {
        std::array<std::uint8_t, 4> got{};
        read(got.data(), 4);
        if (got != kPaddedIntermediateClientStart) throw ProtocolHeaderMismatchError();
    }

    void Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) override {
        detail::CheckOutgoingMessage(payload);
        detail::CheckAlign(payload, 4);

        // Port of writePaddedIntermediate: reads 4 random bytes, then takes
        // `n = payload.back() % 4` extra bytes of padding from what was just
        // read. Go's source indexes the byte at `b.Buf[length-1]` -- the
        // LAST BYTE OF THE PAYLOAD itself, not one of the freshly-read
        // random bytes at `b.Buf[length]` -- which looks like an upstream
        // off-by-one (the padding length ends up payload-dependent, not
        // randomness-dependent). Ported exactly as-is for wire
        // compatibility with this td version; see
        // NOTES/transport-framing-plan.md.
        std::array<std::uint8_t, 4> random_tail{};
        rand_(random_tail.data(), random_tail.size());
        const std::size_t pad_len = payload.empty() ? 0 : (payload.back() % 4);

        std::vector<std::uint8_t> framed = payload;
        framed.insert(framed.end(), random_tail.begin(), random_tail.begin() + static_cast<long>(pad_len));
        detail::WriteIntermediateFrame(write, framed);
    }

    std::vector<std::uint8_t> Read(const ReadExact& read) override {
        auto payload = detail::ReadIntermediateFrame(read, /*padding=*/true);
        detail::CheckProtocolError(payload);
        return payload;
    }

private:
    crypto::RandomFill rand_;
};

} // namespace shuzagram::mtproto::transport
