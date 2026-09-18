// Manual dev tool, not run by ctest: connects to a running shuzagram_server
// (or any TcpHandshakeServer) and performs one real handshake over TCP,
// printing the resulting auth_key_id/server_salt on success. Reads the
// server's own private key PEM to derive its public key -- fine for local
// smoke-testing your own dev server, never how a real client would work
// (a real client already trusts the public key out of band).
//
// Usage:
//   ./manual_tcp_client_smoke <host> <port> <path-to-server-rsa-private-key.pem>

#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>

#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"
#include "shuzagram/net/tcp_socket.hpp"

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::transport;

namespace {

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

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <host> <port> <server-rsa-private-key.pem>\n", argv[0]);
        return 2;
    }
    const std::string host = argv[1];
    const auto port = static_cast<std::uint16_t>(std::stoi(argv[2]));

    std::ifstream key_file(argv[3]);
    if (!key_file) {
        std::fprintf(stderr, "cannot open %s\n", argv[3]);
        return 2;
    }
    std::ostringstream pem_stream;
    pem_stream << key_file.rdbuf();
    const crypto::RsaPublicKey server_key = crypto::RsaPrivateKey::FromPkcs1Pem(pem_stream.str()).PublicKey();

    shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect(host, port);
    IntermediateCodec codec;
    codec.WriteHeader(socket.Writer());
    std::printf("connected to %s:%u, sending req_pq_multi over Intermediate transport\n", host.c_str(), port);

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

    using namespace messages;
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
    std::printf("got resPQ, server fingerprint=%llx\n",
                static_cast<unsigned long long>(res.server_public_key_fingerprints.at(0)));

    std::mt19937_64 rng(std::random_device{}());
    const auto [p, q] = DecomposePq(BytesToU64(res.pq), rng);
    const auto p_bytes = U64ToMinimalBytes(p);
    const auto q_bytes = U64ToMinimalBytes(q);
    const Int256 new_nonce = RandomInt256();
    std::printf("factored pq into p/q\n");

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
    std::printf("got server_DH_params_ok\n");

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
    const auto auth_key_bytes = crypto::ModPowFixed(server_inner.g_a, client_secret_b, server_inner.dh_prime, 256);

    std::array<std::uint8_t, 256> auth_key{};
    std::copy(auth_key_bytes.begin(), auth_key_bytes.end(), auth_key.begin());
    const auto auth_key_id = crypto::AuthKeyId(auth_key);
    const std::int64_t server_salt = crypto::ServerSalt(new_nonce, res.server_nonce);

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
    if (gen_ok.new_nonce_hash1 != crypto::NonceHash1(new_nonce, auth_key)) {
        std::fprintf(stderr, "FAIL: new_nonce_hash1 mismatch\n");
        return 1;
    }

    std::printf("SUCCESS: handshake complete over real TCP against a real server process\n");
    std::printf("auth_key_id=");
    for (const auto b : auth_key_id) std::printf("%02x", b);
    std::printf(" server_salt=%lld\n", static_cast<long long>(server_salt));
    return 0;
}
