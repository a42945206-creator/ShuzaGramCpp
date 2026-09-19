#include "shuzagram/mtproto/transport/detect_transport.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

#include "shuzagram/mtproto/transport/abridged_codec.hpp"
#include "shuzagram/mtproto/transport/full_codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/transport/obfuscated2.hpp"

namespace shuzagram::mtproto::transport {
namespace {

// isHTTPHeaderPrefix + the standalone 0x02010316 check in
// detectTCPTransport (same-port HTTP mux markers this project doesn't
// serve, and one reserved-for-unknown-reasons value straight from the Go
// source's own "????" comment) -- rejected outright rather than
// misinterpreted as an obfuscated2 init.
bool IsReservedPrefix(const std::array<std::uint8_t, 4>& b) {
    static constexpr std::array<std::array<std::uint8_t, 4>, 4> kReservedAscii = {{
        {'G', 'E', 'T', ' '},
        {'P', 'O', 'S', 'T'},
        {'H', 'E', 'A', 'D'},
        {'O', 'P', 'T', 'I'},
    }};
    for (const auto& reserved : kReservedAscii) {
        if (b == reserved) return true;
    }
    // 0x02010316 as a little-endian uint32, i.e. these exact bytes in wire order.
    return b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x01 && b[3] == 0x02;
}

} // namespace

DetectedTransport DetectTransport(const ReadExact& raw_read, const WriteBytes& raw_write,
                                   const std::vector<std::uint8_t>& obfuscated_secret) {
    std::array<std::uint8_t, 8> prefix{};
    raw_read(prefix.data(), 1);

    if (prefix[0] == kAbridgedClientStart) {
        return {std::make_shared<AbridgedCodec>(), raw_read, raw_write};
    }

    raw_read(prefix.data() + 1, 3);
    std::array<std::uint8_t, 4> first4{};
    std::copy(prefix.begin(), prefix.begin() + 4, first4.begin());
    if (first4 == kIntermediateClientStart) {
        return {std::make_shared<IntermediateCodec>(), raw_read, raw_write};
    }
    if (first4 == kPaddedIntermediateClientStart) {
        return {std::make_shared<PaddedIntermediateCodec>(), raw_read, raw_write};
    }
    if (IsReservedPrefix(first4)) {
        throw InvalidTransportPrefixError("reserved transport prefix");
    }

    raw_read(prefix.data() + 4, 4);
    const bool tail_is_zero = prefix[4] == 0 && prefix[5] == 0 && prefix[6] == 0 && prefix[7] == 0;
    if (tail_is_zero) {
        // Plain Full: obfuscated2's nonce generation guarantees bytes 4:8 of
        // a real init are never all zero, while Full's first frame always
        // has transport sequence number 0 there -- so an all-zero tail
        // unambiguously means Full, not a probabilistic guess. These 8
        // bytes are the start of that first frame ([length][seq_no]) and
        // must be replayed before any further read.
        auto replay = std::make_shared<std::array<std::uint8_t, 8>>(prefix);
        auto replay_pos = std::make_shared<std::size_t>(0);
        ReadExact wrapped = [raw_read, replay, replay_pos](std::uint8_t* dst, std::size_t len) {
            const std::size_t from_replay = std::min(len, replay->size() - *replay_pos);
            if (from_replay > 0) {
                std::memcpy(dst, replay->data() + *replay_pos, from_replay);
                *replay_pos += from_replay;
            }
            if (from_replay < len) raw_read(dst + from_replay, len - from_replay);
        };
        return {std::make_shared<FullCodec>(), wrapped, raw_write};
    }

    // Obfuscated2: these 8 bytes are the start of the 64-byte random init.
    std::array<std::uint8_t, 64> init{};
    std::copy(prefix.begin(), prefix.end(), init.begin());
    raw_read(init.data() + 8, 56);

    auto accepted = std::make_shared<Obfuscated2AcceptResult>(AcceptObfuscated2(init, obfuscated_secret));

    ReadExact deobfuscated_read = [raw_read, accepted](std::uint8_t* dst, std::size_t len) {
        raw_read(dst, len);
        accepted->keys.decrypt.XorKeyStream(dst, dst, len);
    };
    WriteBytes obfuscated_write = [raw_write, accepted](const std::uint8_t* src, std::size_t len) {
        std::vector<std::uint8_t> buf(src, src + len);
        accepted->keys.encrypt.XorKeyStream(buf.data(), buf.data(), len);
        raw_write(buf.data(), buf.size());
    };

    const auto& tag = accepted->metadata.protocol;
    if (tag == AbridgedCodec::ObfuscatedTag()) {
        return {std::make_shared<AbridgedCodec>(), deobfuscated_read, obfuscated_write};
    }
    if (tag == kIntermediateClientStart) {
        return {std::make_shared<IntermediateCodec>(), deobfuscated_read, obfuscated_write};
    }
    if (tag == kPaddedIntermediateClientStart) {
        return {std::make_shared<PaddedIntermediateCodec>(), deobfuscated_read, obfuscated_write};
    }
    throw InvalidTransportPrefixError("unrecognized obfuscated2 inner protocol tag");
}

} // namespace shuzagram::mtproto::transport
