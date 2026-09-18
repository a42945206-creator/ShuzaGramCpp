#include "shuzagram/mtproto/transport/full_codec.hpp"

#include <cstring>

#include "crc32.hpp"

// Go's *Full guards write_seq_no/read_seq_no with atomic.AddInt64 because a
// single *Full value there can, in principle, be shared across goroutines
// issuing concurrent Read/Write calls on the same net.Conn. This port's
// connection model (ServerExchange and everything downstream) drives one
// blocking read call and one blocking write call at a time, never two
// concurrent writers or two concurrent readers on the same codec instance
// -- so plain (non-atomic) counters are equivalent here, not a shortcut.
namespace shuzagram::mtproto::transport {

void FullCodec::Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) {
    detail::CheckOutgoingMessage(payload);

    const std::int64_t seq_no = write_seq_no_++;
    const auto total_len = static_cast<std::uint32_t>(4 + 4 + payload.size() + 4);

    std::vector<std::uint8_t> frame;
    frame.reserve(total_len);
    const auto append_u32 = [&frame](std::uint32_t v) {
        frame.push_back(static_cast<std::uint8_t>(v));
        frame.push_back(static_cast<std::uint8_t>(v >> 8));
        frame.push_back(static_cast<std::uint8_t>(v >> 16));
        frame.push_back(static_cast<std::uint8_t>(v >> 24));
    };
    append_u32(total_len);
    append_u32(static_cast<std::uint32_t>(seq_no));
    frame.insert(frame.end(), payload.begin(), payload.end());
    append_u32(detail::Crc32Ieee(frame.data(), frame.size()));

    write(frame.data(), frame.size());
}

std::vector<std::uint8_t> FullCodec::Read(const ReadExact& read) {
    const std::uint32_t n = detail::ReadU32Le(read);
    detail::CheckMessageLength(n);
    if (n < 3 * 4) throw InvalidMessageLengthError(n);

    std::vector<std::uint8_t> frame(n);
    frame[0] = static_cast<std::uint8_t>(n);
    frame[1] = static_cast<std::uint8_t>(n >> 8);
    frame[2] = static_cast<std::uint8_t>(n >> 16);
    frame[3] = static_cast<std::uint8_t>(n >> 24);
    read(frame.data() + 4, n - 4);

    std::uint32_t server_seq_no;
    std::memcpy(&server_seq_no, frame.data() + 4, 4); // wire is little-endian, matching every platform this runs on
    const std::int64_t expected_seq_no = read_seq_no_++;
    if (static_cast<std::int64_t>(static_cast<std::int32_t>(server_seq_no)) != expected_seq_no) {
        throw std::runtime_error("full transport: seq_no mismatch");
    }

    std::uint32_t received_crc;
    std::memcpy(&received_crc, frame.data() + (n - 4), 4);
    const std::uint32_t computed_crc = detail::Crc32Ieee(frame.data(), n - 4);
    if (received_crc != computed_crc) throw std::runtime_error("full transport: crc mismatch");

    std::vector<std::uint8_t> payload(frame.begin() + 8, frame.end() - 4);
    detail::CheckProtocolError(payload);
    return payload;
}

} // namespace shuzagram::mtproto::transport
