#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

// Port of gotd/td's bin.Buffer (github.com/iamxvbaba/td/bin) -- the raw TL
// (Type Language) wire encoder/decoder MTProto itself is built on. See
// https://core.telegram.org/mtproto/serialize.
//
// Simplification vs. the Go source: Go's bin.Buffer re-slices Buf []byte on
// read (b.Buf = b.Buf[n:]), an O(1) pointer/length update. This port erases
// consumed bytes from the front of a std::vector instead (O(n) per read).
// Fine at handshake-message sizes (a few hundred bytes, once per
// connection); revisit with an offset-tracking view if this buffer is ever
// reused on the hot RPC path.
namespace shuzagram::mtproto {

using Int128 = std::array<std::uint8_t, 16>;
using Int256 = std::array<std::uint8_t, 32>;

class UnexpectedIdError : public std::runtime_error {
public:
    explicit UnexpectedIdError(std::uint32_t id)
        : std::runtime_error("unexpected TL id"), id_(id) {}
    std::uint32_t id() const { return id_; }

private:
    std::uint32_t id_;
};

class BufferUnderrunError : public std::runtime_error {
public:
    BufferUnderrunError() : std::runtime_error("unexpected end of TL buffer") {}
};

class TLBuffer {
public:
    // Basic TL type ids (bin/bin.go).
    static constexpr std::uint32_t kTypeVector = 0x1cb5c415;

    std::vector<std::uint8_t> buf;

    void Reset() { buf.clear(); }
    void ResetTo(std::vector<std::uint8_t> data) { buf = std::move(data); }
    [[nodiscard]] std::size_t Len() const { return buf.size(); }

    // --- writing ---

    void Put(const std::uint8_t* data, std::size_t len) { buf.insert(buf.end(), data, data + len); }
    void Put(const std::vector<std::uint8_t>& data) { Put(data.data(), data.size()); }

    void PutUint32(std::uint32_t v) {
        std::uint8_t b[4] = {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
                              static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24)};
        Put(b, 4);
    }
    void PutInt32(std::int32_t v) { PutUint32(static_cast<std::uint32_t>(v)); }
    void PutID(std::uint32_t id) { PutUint32(id); }

    void PutUint64(std::uint64_t v) {
        std::uint8_t b[8];
        for (int i = 0; i < 8; ++i) b[i] = static_cast<std::uint8_t>(v >> (8 * i));
        Put(b, 8);
    }
    void PutLong(std::int64_t v) { PutUint64(static_cast<std::uint64_t>(v)); }

    void PutInt128(const Int128& v) { Put(v.data(), v.size()); }
    void PutInt256(const Int256& v) { Put(v.data(), v.size()); }

    // TL `bytes`: a length-prefixed, then padded-to-a-multiple-of-4 byte
    // string. Lengths <= 253 use a 1-byte prefix; longer ones use a 4-byte
    // prefix whose first byte is the 254 marker (bin/bytes.go).
    void PutBytes(const std::vector<std::uint8_t>& v) {
        static constexpr std::size_t kMaxSmall = 253;
        static constexpr std::uint8_t kLongMarker = 254;
        const std::size_t l = v.size();
        std::size_t header_len;
        if (l <= kMaxSmall) {
            buf.push_back(static_cast<std::uint8_t>(l));
            header_len = 1;
        } else {
            buf.push_back(kLongMarker);
            buf.push_back(static_cast<std::uint8_t>(l));
            buf.push_back(static_cast<std::uint8_t>(l >> 8));
            buf.push_back(static_cast<std::uint8_t>(l >> 16));
            header_len = 4;
        }
        Put(v.data(), v.size());
        const std::size_t current = header_len + l;
        const std::size_t padded = NearestPaddedLength(current);
        buf.insert(buf.end(), padded - current, 0);
    }

    void PutVectorHeader(std::size_t length) {
        PutID(kTypeVector);
        PutInt32(static_cast<std::int32_t>(length));
    }

    // --- reading ---

    [[nodiscard]] std::uint32_t PeekID() const {
        if (buf.size() < 4) throw BufferUnderrunError();
        return ReadU32LE(buf.data());
    }

    void PeekN(std::uint8_t* target, std::size_t n) const {
        if (buf.size() < n) throw BufferUnderrunError();
        std::memcpy(target, buf.data(), n);
    }

    void ConsumeN(std::uint8_t* target, std::size_t n) {
        PeekN(target, n);
        buf.erase(buf.begin(), buf.begin() + static_cast<long>(n));
    }

    std::uint32_t Uint32() {
        const std::uint32_t v = PeekID();
        buf.erase(buf.begin(), buf.begin() + 4);
        return v;
    }
    std::int32_t Int32() { return static_cast<std::int32_t>(Uint32()); }
    std::int32_t Int() { return Int32(); }

    void ConsumeID(std::uint32_t id) {
        const std::uint32_t got = PeekID();
        if (got != id) throw UnexpectedIdError(got);
        buf.erase(buf.begin(), buf.begin() + 4);
    }

    std::uint64_t Uint64() {
        if (buf.size() < 8) throw BufferUnderrunError();
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(buf[static_cast<std::size_t>(i)]) << (8 * i);
        buf.erase(buf.begin(), buf.begin() + 8);
        return v;
    }
    std::int64_t Long() { return static_cast<std::int64_t>(Uint64()); }

    Int128 GetInt128() {
        if (buf.size() < 16) throw BufferUnderrunError();
        Int128 v{};
        std::memcpy(v.data(), buf.data(), 16);
        buf.erase(buf.begin(), buf.begin() + 16);
        return v;
    }
    Int256 GetInt256() {
        if (buf.size() < 32) throw BufferUnderrunError();
        Int256 v{};
        std::memcpy(v.data(), buf.data(), 32);
        buf.erase(buf.begin(), buf.begin() + 32);
        return v;
    }

    std::vector<std::uint8_t> GetBytes() {
        if (buf.empty()) throw BufferUnderrunError();
        static constexpr std::uint8_t kLongMarker = 254;
        std::size_t header_len;
        std::size_t len;
        if (buf[0] == kLongMarker) {
            if (buf.size() < 4) throw BufferUnderrunError();
            len = static_cast<std::size_t>(buf[1]) | (static_cast<std::size_t>(buf[2]) << 8) |
                  (static_cast<std::size_t>(buf[3]) << 16);
            header_len = 4;
        } else {
            len = buf[0];
            header_len = 1;
        }
        if (buf.size() < header_len + len) throw BufferUnderrunError();
        std::vector<std::uint8_t> v(buf.begin() + static_cast<long>(header_len),
                                     buf.begin() + static_cast<long>(header_len + len));
        const std::size_t padded = NearestPaddedLength(header_len + len);
        if (buf.size() < padded) throw BufferUnderrunError();
        buf.erase(buf.begin(), buf.begin() + static_cast<long>(padded));
        return v;
    }

    std::int32_t VectorHeader() {
        ConsumeID(kTypeVector);
        return Int32();
    }

private:
    static std::size_t NearestPaddedLength(std::size_t l) {
        constexpr std::size_t kWord = 4;
        std::size_t n = kWord * (l / kWord);
        if (n < l) n += kWord;
        return n;
    }

    static std::uint32_t ReadU32LE(const std::uint8_t* p) {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }
};

} // namespace shuzagram::mtproto
