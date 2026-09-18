#pragma once

#include "shuzagram/mtproto/transport/codec.hpp"

// Port of proto/codec/full.go: the one built-in transport with no
// connection header and its own per-direction sequence numbers + a CRC32
// integrity check on every frame.
// https://core.telegram.org/mtproto/mtproto-transports#full
namespace shuzagram::mtproto::transport {

class FullCodec final : public Codec {
public:
    // Full has no header: WriteHeader/ReadHeader are no-ops, matching the Go
    // source exactly (it never even reads/writes anything here).
    void WriteHeader(const WriteBytes&) override {}
    void ReadHeader(const ReadExact&) override {}

    void Write(const WriteBytes& write, const std::vector<std::uint8_t>& payload) override;
    std::vector<std::uint8_t> Read(const ReadExact& read) override;

private:
    // Independent per-direction counters (this project's read/write paths
    // for one connection are each driven sequentially, never concurrently,
    // so these don't need to be atomic the way Go's are -- see the header
    // comment in full_codec.cpp).
    std::int64_t write_seq_no_ = 0;
    std::int64_t read_seq_no_ = 0;
};

} // namespace shuzagram::mtproto::transport
