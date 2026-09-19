// Tests for transport::DetectTransport: the combined plain/obfuscated2
// detector that replaces a bare DetectCodec call at the real TCP entry
// point (see NOTES/obfuscated2-transport-plan.md for why this exists --
// real clients default to obfuscated2, which DetectCodec alone
// misinterprets as a bogus Full frame length).

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "shuzagram/mtproto/transport/abridged_codec.hpp"
#include "shuzagram/mtproto/transport/detect_transport.hpp"
#include "shuzagram/mtproto/transport/full_codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/transport/obfuscated2.hpp"

namespace {

using namespace shuzagram::mtproto::transport;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

class ByteBuffer {
public:
    WriteBytes Writer() {
        return [this](const std::uint8_t* data, std::size_t len) { buf_.insert(buf_.end(), data, data + len); };
    }
    ReadExact Reader() {
        return [this](std::uint8_t* dst, std::size_t len) {
            if (buf_.size() < len) throw std::runtime_error("ByteBuffer: short read");
            std::memcpy(dst, buf_.data(), len);
            buf_.erase(buf_.begin(), buf_.begin() + static_cast<long>(len));
        };
    }
    void Append(const std::vector<std::uint8_t>& data) { buf_.insert(buf_.end(), data.begin(), data.end()); }
    [[nodiscard]] const std::vector<std::uint8_t>& Raw() const { return buf_; }
    void Clear() { buf_.clear(); }

private:
    std::vector<std::uint8_t> buf_;
};

std::vector<std::uint8_t> MakePayload(std::size_t len, std::uint8_t seed) {
    std::vector<std::uint8_t> v(len);
    for (std::size_t i = 0; i < len; ++i) v[i] = static_cast<std::uint8_t>(seed + i);
    return v;
}

void TestPlainAbridgedStillWorks() {
    ByteBuffer buf;
    AbridgedCodec writer_codec;
    writer_codec.WriteHeader(buf.Writer());
    const auto payload = MakePayload(8, 1);
    writer_codec.Write(buf.Writer(), payload);

    auto detected = DetectTransport(buf.Reader(), buf.Writer());
    Check(dynamic_cast<AbridgedCodec*>(detected.codec.get()) != nullptr, "plain abridged marker selects AbridgedCodec");
    const auto got = detected.codec->Read(detected.read);
    Check(got == payload, "plain abridged payload round-trips through DetectTransport unchanged");
}

void TestPlainFullReplaysAllEightBytes() {
    ByteBuffer buf;
    FullCodec writer_codec;
    const auto payload = MakePayload(12, 5);
    writer_codec.Write(buf.Writer(), payload); // first frame: seq_no == 0, satisfying the tail-is-zero rule

    auto detected = DetectTransport(buf.Reader(), buf.Writer());
    Check(dynamic_cast<FullCodec*>(detected.codec.get()) != nullptr,
          "a zero seq_no tail selects FullCodec, not obfuscated2");
    const auto got = detected.codec->Read(detected.read);
    Check(got == payload, "Full's first 8 bytes (length+seq_no) are correctly replayed, not consumed");
}

void TestReservedPrefixIsRejected() {
    ByteBuffer buf;
    buf.Append({'G', 'E', 'T', ' ', '/', ' ', 'H', 'T'});
    bool threw = false;
    try {
        DetectTransport(buf.Reader(), buf.Writer());
    } catch (const InvalidTransportPrefixError&) {
        threw = true;
    }
    Check(threw, "an HTTP-looking prefix is rejected outright, not misread as obfuscated2");
}

// Builds the 64-byte obfuscated2 wire header a real client would send:
// bytes 0:56 raw (they ARE the key material), bytes 56:64 = the client's
// own encrypt stream applied to protocol+dc+padding.
std::array<std::uint8_t, 64> BuildClientHeader(const std::array<std::uint8_t, 64>& raw_init,
                                                const std::array<std::uint8_t, 4>& protocol, std::uint16_t dc,
                                                shuzagram::mtproto::crypto::Aes256CtrStream& client_encrypt) {
    std::array<std::uint8_t, 64> wire = raw_init;
    wire[56] = protocol[0];
    wire[57] = protocol[1];
    wire[58] = protocol[2];
    wire[59] = protocol[3];
    wire[60] = static_cast<std::uint8_t>(dc & 0xFF);
    wire[61] = static_cast<std::uint8_t>(dc >> 8);
    client_encrypt.XorKeyStream(wire.data(), wire.data(), wire.size());
    std::copy(raw_init.begin(), raw_init.begin() + 56, wire.begin());
    return wire;
}

void TestObfuscated2SelectsInnerCodecAndDecryptsPayload() {
    std::array<std::uint8_t, 64> raw_init{};
    for (std::size_t i = 0; i < raw_init.size(); ++i) raw_init[i] = static_cast<std::uint8_t>((i * 53 + 7) & 0xFF);
    Check(raw_init[4] != 0 || raw_init[5] != 0 || raw_init[6] != 0 || raw_init[7] != 0,
          "fixture satisfies obfuscated2's non-zero-tail rule (sanity check on the fixture itself)");

    const std::vector<std::uint8_t> no_secret;
    auto client_keys = CreateObfuscated2Streams(raw_init, no_secret);
    const auto wire_header = BuildClientHeader(raw_init, AbridgedCodec::ObfuscatedTag(), /*dc=*/3, client_keys.encrypt);

    // The client's first real frame: an Abridged-encoded payload, THEN
    // encrypted with the same continuing client_keys.encrypt stream (now at
    // keystream position 64).
    ByteBuffer plain_frame;
    AbridgedCodec client_codec;
    const auto payload = MakePayload(16, 9);
    client_codec.Write(plain_frame.Writer(), payload);
    std::vector<std::uint8_t> encrypted_frame = plain_frame.Raw();
    client_keys.encrypt.XorKeyStream(encrypted_frame.data(), encrypted_frame.data(), encrypted_frame.size());

    ByteBuffer wire;
    wire.Append({wire_header.begin(), wire_header.end()});
    wire.Append(encrypted_frame);

    auto detected = DetectTransport(wire.Reader(), wire.Writer());
    Check(dynamic_cast<AbridgedCodec*>(detected.codec.get()) != nullptr,
          "obfuscated2's inner protocol tag 0xefefefef selects AbridgedCodec");
    const auto got = detected.codec->Read(detected.read);
    Check(got == payload, "the obfuscated, then abridged-framed, payload decrypts and decodes back to the original");

    // Now the server->client direction: DetectTransport's returned `write`
    // must encrypt with the swapped stream, which the CLIENT would decrypt
    // with client_keys.decrypt (untouched so far, still at position 0).
    ByteBuffer server_out;
    // Route detected.write through a fresh buffer instead of `wire`'s
    // (which DetectTransport already bound its write to `wire.Writer()`) --
    // rebuild detection isn't needed; `wire`'s writer IS what detected.write
    // wraps, so just read what accumulated in `wire` after the request read.
    const auto reply_payload = MakePayload(8, 42); // Abridged requires 4-byte-aligned payloads
    const std::size_t before = wire.Raw().size();
    detected.codec->Write(detected.write, reply_payload);
    const std::vector<std::uint8_t> on_wire(wire.Raw().begin() + static_cast<long>(before), wire.Raw().end());

    std::vector<std::uint8_t> decrypted = on_wire;
    client_keys.decrypt.XorKeyStream(decrypted.data(), decrypted.data(), decrypted.size());

    ByteBuffer expected_plain;
    AbridgedCodec fresh_codec;
    fresh_codec.Write(expected_plain.Writer(), reply_payload);
    Check(decrypted == expected_plain.Raw(),
          "the server's obfuscated write, decrypted with the client's own decrypt stream, matches a plain "
          "AbridgedCodec encoding of the same reply");
}

} // namespace

int main() {
    TestPlainAbridgedStillWorks();
    TestPlainFullReplaysAllEightBytes();
    TestReservedPrefixIsRejected();
    TestObfuscated2SelectsInnerCodecAndDecryptsPayload();
    if (g_failures == 0) {
        std::printf("all detect_transport tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d detect_transport test(s) failed\n", g_failures);
    return 1;
}
