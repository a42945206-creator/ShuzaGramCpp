// Proves the real TCP wiring works: TcpHandshakeServer listens on an
// actual loopback port (127.0.0.1, OS-assigned), and a fake client connects
// with a real TCP socket (::connect(), not an in-memory pipe) and drives
// the same client protocol as the earlier integration test. Success is the
// same bar as before -- client and server independently derive the
// identical auth_key/server_salt -- except every byte now actually
// travelled through the kernel's TCP/IP stack on loopback.

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <random>
#include <thread>

#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/tcp_handshake_server.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"
#include "shuzagram/net/tcp_socket.hpp"

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

// --- same test-only pq factorization as the other end-to-end tests ---
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

ClientResult RunFakeClientOverRealTcp(std::uint16_t port, const crypto::RsaPublicKey& server_key,
                                       std::mt19937_64& rng) {
    using namespace messages;

    shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
    IntermediateCodec codec;
    codec.WriteHeader(socket.Writer());

    auto send = [&](MessageType type, const TLBuffer& payload) {
        UnencryptedMessage msg;
        msg.message_id = MessageId::New(std::chrono::system_clock::now(), type).Raw();
        msg.message_data = payload.buf;
        TLBuffer framed;
        msg.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);
    };
    auto recv = [&]() -> TLBuffer {
        const auto frame = codec.Read(socket.Reader());
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
          "client recomputes the same new_nonce_hash1 the server sent, over a real TCP socket");

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    TcpHandshakeServer server("127.0.0.1", /*port=*/0, server_private_key);
    const std::uint16_t port = server.Port();
    Check(port != 0, "the OS assigned a real ephemeral port to the listener");

    std::mutex mu;
    std::condition_variable cv;
    bool have_result = false;
    ServerExchangeResult server_result;
    std::string server_failure;

    std::thread server_thread([&] {
        server.Run(
            [&](const ServerExchangeResult& result) {
                std::lock_guard<std::mutex> lock(mu);
                server_result = result;
                have_result = true;
                cv.notify_all();
            },
            [&](const std::string& what) {
                std::lock_guard<std::mutex> lock(mu);
                server_failure = what;
                have_result = true;
                cv.notify_all();
            });
    });

    // Give the accept loop a moment to actually be blocked in accept()
    // before the client dials -- the listener is already bound and
    // listening by the time the constructor returns, so the connection
    // itself won't be refused even without this, but it keeps the test
    // from racing harder than it needs to.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    std::mt19937_64 rng(20260918);
    const ClientResult client_result = RunFakeClientOverRealTcp(port, server_public_key, rng);

    {
        std::unique_lock<std::mutex> lock(mu);
        const bool got_result = cv.wait_for(lock, std::chrono::seconds(10), [&] { return have_result; });
        Check(got_result, "server produced a result within the timeout");
    }

    server.Stop();
    server_thread.join();

    Check(server_failure.empty(), "server did not report a failure (" + server_failure + ")");
    Check(client_result.auth_key == server_result.auth_key,
          "client and server derive the identical auth_key over a real TCP loopback connection");
    Check(client_result.server_salt == server_result.server_salt,
          "client and server derive the identical server_salt over a real TCP loopback connection");

    if (g_failures == 0) {
        std::printf("all net TCP handshake tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d net TCP handshake test(s) failed\n", g_failures);
    return 1;
}
