// Capstone integration test: proves transport framing (this round) and the
// handshake (previous round) actually compose, not just that each passes
// its own isolated tests. A fake client picks a real wire transport
// (Intermediate) and talks pure bytes over two blocking byte-stream pipes
// standing in for a TCP socket's two directions; the server side runs
// DetectCodec on its incoming stream (proving detection works without the
// client's choice being hardcoded anywhere on the server side) and then
// ServerExchange::Run wrapped in that detected codec. Success is the same
// bar as the handshake test: client and server independently derive the
// identical auth_key/server_salt -- except this time every byte that
// crossed the "wire" actually went through real transport framing first.

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/server_exchange.hpp"
#include "shuzagram/mtproto/transport/detect_codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace {

using namespace shuzagram::mtproto;
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

// A blocking byte stream (unlike the handshake test's frame-at-a-time
// FrameChannel, this one is a real byte pipe: a read for N bytes can be
// satisfied by parts of several writes, or block until enough have
// accumulated -- exactly what reading from a TCP socket looks like, which
// is the point: the codec, not this pipe, is what defines frame
// boundaries here.
class StreamPipe {
public:
    void Write(const std::uint8_t* data, std::size_t len) {
        std::lock_guard<std::mutex> lock(mu_);
        buf_.insert(buf_.end(), data, data + len);
        cv_.notify_all();
    }

    void Read(std::uint8_t* dst, std::size_t len) {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [&] { return buf_.size() >= len; });
        std::copy(buf_.begin(), buf_.begin() + static_cast<long>(len), dst);
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<long>(len));
    }

    WriteBytes Writer() {
        return [this](const std::uint8_t* d, std::size_t n) { Write(d, n); };
    }
    ReadExact Reader() {
        return [this](std::uint8_t* d, std::size_t n) { Read(d, n); };
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::uint8_t> buf_;
};

// --- test-only pq factorization, same as mtproto_handshake_test.cpp ---
// (duplicated rather than shared: both are small, self-contained, and
// belong to the test they're in, not to a shared test-support library).
std::uint64_t MulMod(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
    return static_cast<std::uint64_t>((static_cast<unsigned __int128>(a) * b) % m);
}
std::uint64_t Gcd(std::uint64_t a, std::uint64_t b) {
    while (b != 0) {
        const std::uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}
std::pair<std::uint64_t, std::uint64_t> DecomposePq(std::uint64_t pq, std::mt19937_64& rng) {
    const std::uint64_t what = pq;
    std::uint64_t g = 0;
    int i = 0;
    while (!(g > 1 && g < what)) {
        std::uint64_t v = (rng() & 15) + 17;
        v %= what;
        std::uint64_t x = rng() % (what - 1) + 1;
        std::uint64_t y = x;
        const int lim = 1 << (i + 18);
        int j = 1;
        bool flag = true;
        while (j < lim && flag) {
            x = (MulMod(x, x, what) + v) % what;
            const std::uint64_t z = (x < y) ? (what - y + x) : (x - y);
            g = Gcd(z, what);
            if ((j & (j - 1)) == 0) y = x;
            ++j;
            if (g != 1) flag = false;
        }
        ++i;
    }
    std::uint64_t p = g;
    std::uint64_t q = what / g;
    if (p > q) std::swap(p, q);
    return {p, q};
}
std::uint64_t BytesToU64(const std::vector<std::uint8_t>& b) {
    std::uint64_t v = 0;
    for (const auto byte : b) v = (v << 8) | byte;
    return v;
}
std::vector<std::uint8_t> U64ToMinimalBytes(std::uint64_t v) {
    std::vector<std::uint8_t> out;
    bool started = false;
    for (int i = 7; i >= 0; --i) {
        const auto byte = static_cast<std::uint8_t>(v >> (8 * i));
        if (byte != 0) started = true;
        if (started) out.push_back(byte);
    }
    if (out.empty()) out.push_back(0);
    return out;
}
Int128 RandomInt128() {
    Int128 out{};
    const auto r = crypto::SystemRandomBytes(16);
    std::copy(r.begin(), r.end(), out.begin());
    return out;
}
Int256 RandomInt256() {
    Int256 out{};
    const auto r = crypto::SystemRandomBytes(32);
    std::copy(r.begin(), r.end(), out.begin());
    return out;
}

struct ClientResult {
    std::array<std::uint8_t, 256> auth_key{};
    std::int64_t server_salt = 0;
};

// Same protocol steps as the handshake test's fake client, but every
// send/receive now goes through a real Codec over a real byte stream
// instead of a frame-granular queue.
ClientResult RunFakeClientOverTransport(Codec& codec, const WriteBytes& write, const ReadExact& read,
                                         const crypto::RsaPublicKey& server_key, std::mt19937_64& rng) {
    using namespace messages;

    auto send = [&](MessageType type, const TLBuffer& payload) {
        UnencryptedMessage msg;
        msg.message_id = MessageId::New(std::chrono::system_clock::now(), type).Raw();
        msg.message_data = payload.buf;
        TLBuffer framed;
        msg.Encode(framed);
        codec.Write(write, framed.buf);
    };
    auto recv = [&]() -> TLBuffer {
        const auto frame = codec.Read(read);
        TLBuffer b;
        b.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(b);
        TLBuffer payload;
        payload.buf = msg.message_data;
        return payload;
    };

    const Int128 nonce = RandomInt128();
    {
        TLBuffer payload;
        payload.PutID(kReqPqMultiRequestTypeId);
        payload.PutInt128(nonce);
        send(MessageType::kFromClient, payload);
    }

    ResPq res;
    {
        TLBuffer b = recv();
        b.ConsumeID(ResPq::kTypeId);
        res.nonce = b.GetInt128();
        res.server_nonce = b.GetInt128();
        res.pq = b.GetBytes();
        const auto count = b.VectorHeader();
        for (int i = 0; i < count; ++i) res.server_public_key_fingerprints.push_back(b.Long());
    }

    const auto [p, q] = DecomposePq(BytesToU64(res.pq), rng);
    const auto p_bytes = U64ToMinimalBytes(p);
    const auto q_bytes = U64ToMinimalBytes(q);
    const Int256 new_nonce = RandomInt256();

    std::vector<std::uint8_t> encrypted_data;
    {
        TLBuffer inner_encoded;
        inner_encoded.PutID(PqInnerData::kPlainTypeId);
        inner_encoded.PutBytes(res.pq);
        inner_encoded.PutBytes(p_bytes);
        inner_encoded.PutBytes(q_bytes);
        inner_encoded.PutInt128(res.nonce);
        inner_encoded.PutInt128(res.server_nonce);
        inner_encoded.PutInt256(new_nonce);
        encrypted_data = crypto::RsaPad(inner_encoded.buf, server_key);
    }
    {
        TLBuffer payload;
        payload.PutID(ReqDhParams::kTypeId);
        payload.PutInt128(res.nonce);
        payload.PutInt128(res.server_nonce);
        payload.PutBytes(p_bytes);
        payload.PutBytes(q_bytes);
        payload.PutLong(res.server_public_key_fingerprints.at(0));
        payload.PutBytes(encrypted_data);
        send(MessageType::kFromClient, payload);
    }

    ServerDhParamsOk ok;
    {
        TLBuffer b = recv();
        b.ConsumeID(ServerDhParamsOk::kTypeId);
        ok.nonce = b.GetInt128();
        ok.server_nonce = b.GetInt128();
        ok.encrypted_answer = b.GetBytes();
    }

    std::vector<std::uint8_t> temp_key, temp_iv;
    crypto::TempAesKeys(new_nonce, res.server_nonce, temp_key, temp_iv);

    ServerDhInnerData server_inner;
    {
        const auto decrypted = crypto::DecryptExchangeAnswer(ok.encrypted_answer, temp_key, temp_iv);
        TLBuffer b;
        b.buf = decrypted;
        b.ConsumeID(ServerDhInnerData::kTypeId);
        server_inner.nonce = b.GetInt128();
        server_inner.server_nonce = b.GetInt128();
        server_inner.g = b.Int();
        server_inner.dh_prime = b.GetBytes();
        server_inner.g_a = b.GetBytes();
        server_inner.server_time = b.Int();
    }

    const std::vector<std::uint8_t> client_secret_b = crypto::SystemRandomBytes(256);
    const std::vector<std::uint8_t> g_bytes = {static_cast<std::uint8_t>(server_inner.g)};
    const auto g_b = crypto::ModPow(g_bytes, client_secret_b, server_inner.dh_prime);

    ClientResult result;
    const auto auth_key_bytes = crypto::ModPowFixed(server_inner.g_a, client_secret_b, server_inner.dh_prime, 256);
    std::copy(auth_key_bytes.begin(), auth_key_bytes.end(), result.auth_key.begin());
    result.server_salt = crypto::ServerSalt(new_nonce, res.server_nonce);

    {
        ClientDhInnerData client_inner;
        client_inner.nonce = res.nonce;
        client_inner.server_nonce = res.server_nonce;
        client_inner.retry_id = 0;
        client_inner.g_b = g_b;
        TLBuffer inner_encoded;
        client_inner.Encode(inner_encoded);
        const auto answer = crypto::EncryptExchangeAnswer(inner_encoded.buf, temp_key, temp_iv);

        TLBuffer payload;
        payload.PutID(SetClientDhParams::kTypeId);
        payload.PutInt128(res.nonce);
        payload.PutInt128(res.server_nonce);
        payload.PutBytes(answer);
        send(MessageType::kFromClient, payload);
    }

    DhGenOk gen_ok;
    {
        TLBuffer b = recv();
        b.ConsumeID(DhGenOk::kTypeId);
        gen_ok.nonce = b.GetInt128();
        gen_ok.server_nonce = b.GetInt128();
        gen_ok.new_nonce_hash1 = b.GetInt128();
    }
    Check(gen_ok.new_nonce_hash1 == crypto::NonceHash1(new_nonce, result.auth_key),
          "client recomputes the same new_nonce_hash1 the server sent, over real transport framing");

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    StreamPipe client_to_server;
    StreamPipe server_to_client;

    ServerExchange exchange(server_private_key);
    ServerExchangeResult server_result;
    std::exception_ptr server_exception;

    std::thread server_thread([&] {
        try {
            // The server does not know in advance which transport the
            // client will pick -- DetectCodec figures it out from the raw
            // stream, exactly as it would on a real listening socket.
            DetectedCodec detected = DetectCodec(client_to_server.Reader());
            server_result = exchange.Run(
                [&] { return detected.codec->Read(detected.read); },
                [&](const std::vector<std::uint8_t>& frame) { detected.codec->Write(server_to_client.Writer(), frame); });
        } catch (...) {
            server_exception = std::current_exception();
        }
    });

    // The client picks Intermediate (arbitrary among the four -- the point
    // is the server never special-cased this choice).
    IntermediateCodec client_codec;
    client_codec.WriteHeader(client_to_server.Writer());

    std::mt19937_64 rng(424242);
    const ClientResult client_result = RunFakeClientOverTransport(
        client_codec, client_to_server.Writer(), server_to_client.Reader(), server_public_key, rng);

    server_thread.join();
    if (server_exception) {
        try {
            std::rethrow_exception(server_exception);
        } catch (const std::exception& e) {
            Check(false, std::string("server exchange threw: ") + e.what());
        }
    } else {
        Check(true, "server exchange completed without throwing, driven entirely through DetectCodec + Intermediate");
    }

    Check(client_result.auth_key == server_result.auth_key,
          "client and server derive the identical auth_key end to end over real transport framing");
    Check(client_result.server_salt == server_result.server_salt,
          "client and server derive the identical server_salt end to end over real transport framing");

    // Full-chain capstone: the auth_key this handshake just produced (over
    // real transport framing, not a bare in-memory frame queue) actually
    // works to encrypt/decrypt an ordinary post-handshake message -- the
    // thing all of this exists to make possible. Uses
    // crypto::EncryptMessage/DecryptMessage directly (already verified
    // against official vectors in mtproto_message_cipher_test.cpp); the
    // point here is only that the auth_key from THIS pipeline is a valid
    // key for THAT cipher, not re-testing the cipher itself.
    {
        using namespace shuzagram::mtproto::crypto;
        const std::vector<std::uint8_t> rpc_message = {'p', 'i', 'n', 'g', 0, 0, 0, 0};
        const EncryptedMessage wire = EncryptMessage(client_result.auth_key, client_result.server_salt,
                                                      /*session_id=*/987654321, /*message_id=*/1, /*seq_no=*/1,
                                                      rpc_message, Side::kClient);
        const EncryptedMessageData decrypted = DecryptMessage(server_result.auth_key, wire, Side::kServer);
        Check(decrypted.message_data == rpc_message,
              "the handshake's own auth_key correctly encrypts (as client) and decrypts (as server) a real message");
        Check(decrypted.salt == client_result.server_salt, "decrypted message carries the handshake's own server_salt");
    }

    if (g_failures == 0) {
        std::printf("all mtproto integration tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto integration test(s) failed\n", g_failures);
    return 1;
}
