// Tests for the MTProto wire-transport codecs (abridged/intermediate/
// padded-intermediate/full) and DetectCodec. Round-trips a payload through
// each codec's own Write then Read (an in-memory byte buffer standing in
// for the TCP stream) and checks DetectCodec picks the right one from each
// transport's real client marker bytes -- including Full, which has no
// marker and needs its already-consumed first 4 bytes replayed.

#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "shuzagram/mtproto/transport/abridged_codec.hpp"
#include "shuzagram/mtproto/transport/detect_codec.hpp"
#include "shuzagram/mtproto/transport/full_codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"

namespace {

using namespace shuzagram::mtproto::transport;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (ok) {
        std::printf("ok: %s\n", what.c_str());
    } else {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// A byte buffer that's both writable (appends) and, separately, readable
// (consumes from the front) -- enough to stand in for a TCP stream when
// the test drives write-then-read itself, single-threaded.
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
    [[nodiscard]] std::size_t Remaining() const { return buf_.size(); }

private:
    std::vector<std::uint8_t> buf_;
};

std::vector<std::uint8_t> MakePayload(std::size_t len, std::uint8_t seed) {
    std::vector<std::uint8_t> v(len);
    for (std::size_t i = 0; i < len; ++i) v[i] = static_cast<std::uint8_t>(seed + i);
    return v;
}

void TestCodecRoundTrip(Codec& codec, std::size_t len, const std::string& label) {
    ByteBuffer channel;
    const auto payload = MakePayload(len, 0x11);
    codec.Write(channel.Writer(), payload);
    const auto got = codec.Read(channel.Reader());
    Check(got == payload, label + ": round-trips a " + std::to_string(len) + "-byte payload");
    Check(channel.Remaining() == 0, label + ": leaves no trailing bytes after Read");
}

void TestAbridgedRoundTrips() {
    AbridgedCodec codec;
    TestCodecRoundTrip(codec, 8, "Abridged");
    TestCodecRoundTrip(codec, 400, "Abridged");
    // >= 127 words (508 bytes) forces the extended 4-byte length header.
    TestCodecRoundTrip(codec, 600, "Abridged (extended length header)");
}

void TestIntermediateRoundTrips() {
    IntermediateCodec codec;
    TestCodecRoundTrip(codec, 8, "Intermediate");
    TestCodecRoundTrip(codec, 1000, "Intermediate");
}

void TestPaddedIntermediateRoundTrips() {
    PaddedIntermediateCodec codec;
    // Payload length itself must still be a multiple of 4 (checkAlign);
    // the codec appends its own 0-3 extra padding bytes on top, which Read
    // must strip back off transparently.
    for (std::size_t len : {8, 40, 400}) {
        ByteBuffer channel;
        const auto payload = MakePayload(len, 0x22);
        codec.Write(channel.Writer(), payload);
        Check(channel.Remaining() >= 4 + len, "PaddedIntermediate: wrote at least the payload plus its length prefix");
        const auto got = codec.Read(channel.Reader());
        Check(got == payload, "PaddedIntermediate: round-trips a " + std::to_string(len) + "-byte payload");
    }
}

void TestFullRoundTrips() {
    FullCodec codec;
    // Exercise several frames in a row to prove the seq_no counters advance
    // correctly across repeated calls on the same codec instance.
    for (int i = 0; i < 3; ++i) {
        TestCodecRoundTrip(codec, 16 + static_cast<std::size_t>(i) * 4, "Full (frame " + std::to_string(i) + ")");
    }
}

void TestFullRejectsSeqNoMismatch() {
    // Two independent codec instances -- as if two peers each started their
    // own seq_no count at 0 -- can't validly read each other's frames if a
    // frame from the wrong sequence position is spliced in.
    FullCodec writer;
    ByteBuffer channel;
    writer.Write(channel.Writer(), MakePayload(8, 0x33));
    // Skip straight to reading a *second* frame's position with a fresh
    // reader codec (which still expects seq_no == 0 first).
    FullCodec reader;
    bool threw = false;
    try {
        reader.Read(channel.Reader());
    } catch (const std::exception&) {
        // First frame (seq_no 0) actually matches a fresh reader's
        // expectation, so this should NOT throw -- verifying the negative
        // case properly needs a genuine mismatch:
        threw = true;
    }
    Check(!threw, "Full: a fresh reader accepts a fresh writer's first frame (both start at seq_no 0)");

    // Now write a second frame from `writer` (seq_no 1) but try to read it
    // with `reader`, which itself is now also expecting seq_no 1 -- so
    // instead prove the mismatch by feeding a hand-crafted frame claiming
    // the wrong seq_no.
    ByteBuffer bad_channel;
    {
        // Manually build a Full frame with seq_no = 5 while `reader` (after
        // the successful read above) expects seq_no == 1 next.
        std::vector<std::uint8_t> payload = MakePayload(4, 0x44);
        std::vector<std::uint8_t> frame;
        const auto put_u32 = [&frame](std::uint32_t v) {
            frame.push_back(static_cast<std::uint8_t>(v));
            frame.push_back(static_cast<std::uint8_t>(v >> 8));
            frame.push_back(static_cast<std::uint8_t>(v >> 16));
            frame.push_back(static_cast<std::uint8_t>(v >> 24));
        };
        put_u32(static_cast<std::uint32_t>(4 + 4 + payload.size() + 4));
        put_u32(5); // wrong seq_no
        frame.insert(frame.end(), payload.begin(), payload.end());
        // CRC over what's written so far, appended -- must still be
        // internally consistent, or the mismatch we're testing for would be
        // masked by a CRC failure instead.
        // (Duplicated CRC32 here on purpose: this test intentionally avoids
        // reaching into the codec's private implementation.)
        std::uint32_t crc = 0xFFFFFFFFu;
        for (auto byte : frame) {
            crc ^= byte;
            for (int b = 0; b < 8; ++b) crc = (crc & 1) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        }
        crc ^= 0xFFFFFFFFu;
        put_u32(crc);
        bad_channel.Writer()(frame.data(), frame.size());
    }
    bool mismatch_thrown = false;
    try {
        reader.Read(bad_channel.Reader());
    } catch (const std::exception&) {
        mismatch_thrown = true;
    }
    Check(mismatch_thrown, "Full: rejects a frame with the wrong seq_no");
}

void TestDetectCodecPicksEachTransport() {
    {
        ByteBuffer channel;
        AbridgedCodec writer;
        const auto payload = MakePayload(8, 0x55);
        writer.WriteHeader(channel.Writer());
        writer.Write(channel.Writer(), payload);
        auto detected = DetectCodec(channel.Reader());
        Check(dynamic_cast<AbridgedCodec*>(detected.codec.get()) != nullptr, "DetectCodec picks Abridged from 0xEF");
        Check(detected.codec->Read(detected.read) == payload, "DetectCodec(Abridged): first frame still decodes");
    }
    {
        ByteBuffer channel;
        IntermediateCodec writer;
        const auto payload = MakePayload(8, 0x66);
        writer.WriteHeader(channel.Writer());
        writer.Write(channel.Writer(), payload);
        auto detected = DetectCodec(channel.Reader());
        Check(dynamic_cast<IntermediateCodec*>(detected.codec.get()) != nullptr,
              "DetectCodec picks Intermediate from EE EE EE EE");
        Check(detected.codec->Read(detected.read) == payload, "DetectCodec(Intermediate): first frame still decodes");
    }
    {
        ByteBuffer channel;
        PaddedIntermediateCodec writer;
        const auto payload = MakePayload(8, 0x77);
        writer.WriteHeader(channel.Writer());
        writer.Write(channel.Writer(), payload);
        auto detected = DetectCodec(channel.Reader());
        Check(dynamic_cast<PaddedIntermediateCodec*>(detected.codec.get()) != nullptr,
              "DetectCodec picks PaddedIntermediate from DD DD DD DD");
        Check(detected.codec->Read(detected.read) == payload,
              "DetectCodec(PaddedIntermediate): first frame still decodes");
    }
    {
        // Full has no header -- the first frame's own length bytes are what
        // DetectCodec sees and must replay.
        ByteBuffer channel;
        FullCodec writer;
        const auto payload = MakePayload(8, 0x88);
        writer.Write(channel.Writer(), payload);
        auto detected = DetectCodec(channel.Reader());
        Check(dynamic_cast<FullCodec*>(detected.codec.get()) != nullptr,
              "DetectCodec falls through to Full when no marker matches");
        Check(detected.codec->Read(detected.read) == payload,
              "DetectCodec(Full): replayed length bytes let the first frame still decode");
    }
}

void TestProtocolErrorFrameIsRecognized() {
    IntermediateCodec codec;
    ByteBuffer channel;
    // A bare 4-byte payload -- exactly what a protocol-level error frame
    // looks like once unwrapped (any real MTProto payload is longer).
    std::int32_t code = -404;
    std::vector<std::uint8_t> raw(4);
    std::memcpy(raw.data(), &code, 4);
    codec.Write(channel.Writer(), raw);

    bool threw_with_right_code = false;
    try {
        codec.Read(channel.Reader());
    } catch (const ProtocolError& e) {
        threw_with_right_code = (e.code() == 404);
    }
    Check(threw_with_right_code, "a 4-byte frame decodes as ProtocolError(404), not as 4 bytes of data");
}

} // namespace

int main() {
    TestAbridgedRoundTrips();
    TestIntermediateRoundTrips();
    TestPaddedIntermediateRoundTrips();
    TestFullRoundTrips();
    TestFullRejectsSeqNoMismatch();
    TestDetectCodecPicksEachTransport();
    TestProtocolErrorFrameIsRecognized();

    if (g_failures == 0) {
        std::printf("all mtproto transport tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto transport test(s) failed\n", g_failures);
    return 1;
}
