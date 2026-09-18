#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// Port of proto/codec/codec.go + errors.go: the abstraction every MTProto
// wire transport (abridged/intermediate/padded-intermediate/full) sits
// behind. This is the layer between raw TCP bytes and the "logical frame"
// bytes shuzagram::mtproto::ServerExchange already consumes -- see
// NOTES/transport-framing-plan.md.
namespace shuzagram::mtproto::transport {

// Reads exactly len bytes into buf, or throws (short read / EOF / socket
// error) -- the C++ analogue of io.ReadFull. Writes exactly len bytes or
// throws.
using ReadExact = std::function<void(std::uint8_t* buf, std::size_t len)>;
using WriteBytes = std::function<void(const std::uint8_t* buf, std::size_t len)>;

// MaxMessageSize (proto/codec/errors.go): the largest transport payload any
// built-in codec accepts, matching gotd/td's own limit (bigger than the
// spec's nominal 1 MB -- see the Go source's own comment/link trail).
inline constexpr std::size_t kMaxMessageSize = 1 << 24; // 16 MB

class InvalidMessageLengthError : public std::runtime_error {
public:
    explicit InvalidMessageLengthError(long long n)
        : std::runtime_error("invalid message length " + std::to_string(n)), n_(n) {}
    [[nodiscard]] long long n() const { return n_; }

private:
    long long n_;
};

class AlignedPayloadExpectedError : public std::runtime_error {
public:
    explicit AlignedPayloadExpectedError(int expected)
        : std::runtime_error("payload is not aligned, expected align by " + std::to_string(expected)) {}
};

class ProtocolHeaderMismatchError : public std::runtime_error {
public:
    ProtocolHeaderMismatchError() : std::runtime_error("protocol header mismatch") {}
};

// checkProtocolError (errors.go): any transport frame that is exactly 4
// bytes is unambiguous -- a real MTProto payload is always longer than
// that -- so the codecs all use this shape to signal a transport/session
// -level failure (auth key not found, wrong DC, transport flood, ...)
// instead of legitimate data.
class ProtocolError : public std::runtime_error {
public:
    explicit ProtocolError(std::int32_t code) : std::runtime_error(MessageFor(code)), code_(code) {}
    [[nodiscard]] std::int32_t code() const { return code_; }

    static constexpr std::int32_t kAuthKeyNotFound = 404;
    static constexpr std::int32_t kWrongDc = 444;
    static constexpr std::int32_t kTransportFlood = 429;

private:
    static std::string MessageFor(std::int32_t code) {
        switch (code) {
            case kAuthKeyNotFound: return "auth key not found";
            case kTransportFlood: return "transport flood";
            case kWrongDc: return "wrong DC";
            default: return "protocol error " + std::to_string(code);
        }
    }
    std::int32_t code_;
};

// Codec is the MTProto transport protocol encoding abstraction. WriteHeader/
// ReadHeader carry the one-time client connection marker some transports
// use; per the protocol spec "the server does not respond with it", so a
// server never calls WriteHeader, and never calls ReadHeader either --
// DetectCodec (detect_codec.hpp) consumes and interprets that marker itself
// while picking which Codec to construct.
class Codec {
public:
    virtual ~Codec() = default;
    virtual void WriteHeader(const WriteBytes& write) = 0;
    virtual void ReadHeader(const ReadExact& read) = 0;
    virtual void Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) = 0;
    virtual std::vector<std::uint8_t> Read(const ReadExact& read) = 0;
};

namespace detail {

inline void CheckMessageLength(std::size_t length) {
    if (length == 0 || length > kMaxMessageSize) throw InvalidMessageLengthError(static_cast<long long>(length));
}

inline void CheckOutgoingMessage(const std::vector<std::uint8_t>& payload) { CheckMessageLength(payload.size()); }

inline void CheckAlign(const std::vector<std::uint8_t>& payload, int n) {
    if (payload.size() % static_cast<std::size_t>(n) != 0) throw AlignedPayloadExpectedError(n);
}

// A frame of exactly 4 bytes is always a protocol error signal, never data.
inline void CheckProtocolError(const std::vector<std::uint8_t>& payload) {
    if (payload.size() != 4) return;
    std::int32_t code;
    std::memcpy(&code, payload.data(), 4); // buffer is little-endian on the wire and on every platform this runs on
    throw ProtocolError(-code);
}

inline void WriteU32Le(const WriteBytes& write, std::uint32_t v) {
    const std::uint8_t b[4] = {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
                                static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24)};
    write(b, 4);
}

inline std::uint32_t ReadU32Le(const ReadExact& read) {
    std::uint8_t b[4];
    read(b, 4);
    return static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8) |
           (static_cast<std::uint32_t>(b[2]) << 16) | (static_cast<std::uint32_t>(b[3]) << 24);
}

} // namespace detail

} // namespace shuzagram::mtproto::transport
