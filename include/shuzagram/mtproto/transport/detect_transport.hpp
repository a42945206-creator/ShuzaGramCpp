#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include "shuzagram/mtproto/transport/codec.hpp"

// Port of the plain/obfuscated split in detectTCPTransport + promoteMixedTCP
// (internal/mtprotoedge/transport_detection.go). Unlike DetectCodec
// (detect_codec.hpp, which only ever sees plaintext framing and is what
// this project used exclusively before this round), DetectTransport also
// transparently accepts obfuscated2 connections -- what a real client
// sends by default -- and wraps read/write in the derived AES-256-CTR
// streams so everything above this layer (ServerExchange, MtprotoSession)
// never needs to know the connection was obfuscated at all. See
// NOTES/obfuscated2-transport-plan.md.
namespace shuzagram::mtproto::transport {

struct DetectedTransport {
    std::shared_ptr<Codec> codec;
    // Use these instead of the raw connection's read/write for every
    // subsequent call: for a plain connection they're identical to what was
    // passed in (modulo Full's own detection replay, same as DetectCodec);
    // for an obfuscated2 connection they transparently de/encrypt.
    ReadExact read;
    WriteBytes write;
};

class InvalidTransportPrefixError : public std::runtime_error {
public:
    explicit InvalidTransportPrefixError(const std::string& what) : std::runtime_error(what) {}
};

// obfuscated_secret is this deployment's MTProxy secret, if any -- empty
// (the default, and this project's own real usage) means "no secret",
// matching a direct DC connection rather than an MTProxy hop.
DetectedTransport DetectTransport(const ReadExact& raw_read, const WriteBytes& raw_write,
                                   const std::vector<std::uint8_t>& obfuscated_secret = {});

} // namespace shuzagram::mtproto::transport
