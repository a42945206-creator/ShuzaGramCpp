#pragma once

#include <array>
#include <cstring>
#include <memory>

#include "shuzagram/mtproto/transport/abridged_codec.hpp"
#include "shuzagram/mtproto/transport/codec.hpp"
#include "shuzagram/mtproto/transport/full_codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"

// Port of transport/detect_codec.go: a server reads at most the first 4
// bytes of a fresh connection to figure out which of the 4 built-in wire
// transports the client picked, since (unlike the other three) Full has no
// distinguishing marker -- its first 4 bytes are simply the length of its
// first real frame, and must be replayed rather than discarded.
namespace shuzagram::mtproto::transport {

struct DetectedCodec {
    std::shared_ptr<Codec> codec;
    // Use this instead of the raw connection's read function for every
    // subsequent Read() call: for the plain three transports it's identical
    // to what was passed in, but for Full it replays the 4 bytes detection
    // already consumed before falling through to the real source.
    ReadExact read;
};

inline DetectedCodec DetectCodec(const ReadExact& raw_read) {
    std::array<std::uint8_t, 4> prefix{};
    raw_read(prefix.data(), 1);

    if (prefix[0] == kAbridgedClientStart) {
        return {std::make_shared<AbridgedCodec>(), raw_read};
    }

    raw_read(prefix.data() + 1, 3);
    if (prefix == kIntermediateClientStart) {
        return {std::make_shared<IntermediateCodec>(), raw_read};
    }
    if (prefix == kPaddedIntermediateClientStart) {
        return {std::make_shared<PaddedIntermediateCodec>(), raw_read};
    }

    // Full: these 4 bytes are the start of the first frame's length field,
    // not a marker -- replay them before any further read.
    auto replay = std::make_shared<std::array<std::uint8_t, 4>>(prefix);
    auto replay_pos = std::make_shared<std::size_t>(0);
    ReadExact wrapped = [raw_read, replay, replay_pos](std::uint8_t* dst, std::size_t len) {
        const std::size_t from_replay = std::min(len, replay->size() - *replay_pos);
        if (from_replay > 0) {
            std::memcpy(dst, replay->data() + *replay_pos, from_replay);
            *replay_pos += from_replay;
        }
        if (from_replay < len) raw_read(dst + from_replay, len - from_replay);
    };
    return {std::make_shared<FullCodec>(), wrapped};
}

} // namespace shuzagram::mtproto::transport
