// The first actually-runnable service binary in this port: listens on a
// real TCP port, autodetects the wire transport per connection, runs the
// MTProto DH handshake, and persists the resulting auth_key to Postgres via
// the store layer built earlier. Everything after a successful handshake
// (RPC dispatch, sessions, update delivery) is not built yet -- the
// connection is simply closed once the auth_key is saved. See
// NOTES/tcp-wiring-plan.md for what's deliberately not here yet.
//
// Configuration is via environment variables (no config file/flags parser
// yet -- this is a first runnable slice, not the final entry point):
//   SHUZAGRAM_BIND_ADDRESS   default "0.0.0.0"
//   SHUZAGRAM_PORT           default 2398 (the port the real ShuzaGram
//                            deployment's TELESRV_SERVER_PORT uses)
//   SHUZAGRAM_RSA_KEY_PATH   default "./shuzagram-server-rsa.pem"
//   SHUZAGRAM_PG_DSN         libpq connection string; if unset, the server
//                            still runs the handshake but doesn't persist
//                            the resulting auth_key anywhere (logged only)

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/tcp_handshake_server.hpp"
#include "shuzagram/store/postgres/auth_key_store.hpp"

namespace {

std::string GetEnvOr(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

std::atomic<shuzagram::mtproto::TcpHandshakeServer*> g_server{nullptr};

void HandleShutdownSignal(int) {
    // Only touches an atomic pointer's Stop() (itself just an atomic
    // store) -- no allocation, no iostream, so this stays within what a
    // signal handler can safely do.
    if (auto* server = g_server.load()) server->Stop();
}

std::string HexEncode(const std::uint8_t* data, std::size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

} // namespace

int main() {
    using namespace shuzagram;

    const std::string bind_address = GetEnvOr("SHUZAGRAM_BIND_ADDRESS", "0.0.0.0");
    const int port = std::atoi(GetEnvOr("SHUZAGRAM_PORT", "2398").c_str());
    const std::string rsa_key_path = GetEnvOr("SHUZAGRAM_RSA_KEY_PATH", "./shuzagram-server-rsa.pem");
    const std::string pg_dsn = GetEnvOr("SHUZAGRAM_PG_DSN", "");

    mtproto::crypto::RsaPrivateKey key = [&] {
        try {
            return mtproto::crypto::RsaPrivateKey::LoadOrGenerate(rsa_key_path);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "failed to load/generate RSA key at %s: %s\n", rsa_key_path.c_str(), e.what());
            std::exit(1);
        }
    }();
    std::printf("RSA key ready (%s), fingerprint=%llx\n", rsa_key_path.c_str(),
                static_cast<unsigned long long>(key.Fingerprint()));

    std::unique_ptr<store::postgres::Database> db;
    std::unique_ptr<store::postgres::AuthKeyStore> auth_key_store;
    if (!pg_dsn.empty()) {
        try {
            db = std::make_unique<store::postgres::Database>(pg_dsn);
            auth_key_store = std::make_unique<store::postgres::AuthKeyStore>(*db);
            std::printf("connected to Postgres; completed handshakes will persist their auth_key\n");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "failed to connect to Postgres (%s): %s -- continuing without persistence\n",
                         pg_dsn.c_str(), e.what());
        }
    } else {
        std::printf("SHUZAGRAM_PG_DSN not set -- completed handshakes will be logged but not persisted\n");
    }

    mtproto::TcpHandshakeServer server(bind_address, static_cast<std::uint16_t>(port), std::move(key));
    std::printf("listening on %s:%d\n", bind_address.c_str(), server.Port());

    g_server.store(&server);
    std::signal(SIGINT, HandleShutdownSignal);
    std::signal(SIGTERM, HandleShutdownSignal);

    server.Run(
        [&](const mtproto::ServerExchangeResult& result) {
            const auto auth_key_id = mtproto::crypto::AuthKeyId(result.auth_key);
            std::printf("handshake completed: auth_key_id=%s server_salt=%lld\n",
                        HexEncode(auth_key_id.data(), auth_key_id.size()).c_str(),
                        static_cast<long long>(result.server_salt));
            if (!auth_key_store) return;
            try {
                store::AuthKeyData data;
                data.id = auth_key_id;
                data.value = result.auth_key;
                data.server_salt = result.server_salt;
                data.expires_at = 0; // permanent key
                auth_key_store->Save(data);
                std::printf("  saved to Postgres\n");
            } catch (const std::exception& e) {
                std::fprintf(stderr, "  failed to persist auth_key: %s\n", e.what());
            }
        },
        [](const std::string& what) { std::fprintf(stderr, "handshake failed: %s\n", what.c_str()); });

    std::printf("shutting down\n");
    std::fflush(stdout);
    // std::_Exit(), not return: the Ubuntu libpqxx 7.10.0 package double-frees a
    // static string during global destruction -- reproducible with a ~10-line
    // program that does nothing but construct a pqxx::connection, and present
    // here even when SHUZAGRAM_PG_DSN was never set, since linking
    // shuzagram_store_postgres alone is enough to register the bad destructor.
    // _Exit() skips static destructors entirely, which is safe here (the
    // process is terminating and the OS reclaims everything) but is not a fix;
    // see the identical note in tests/user_store_smoke.cpp and
    // NOTES/architecture-overview.md.
    std::_Exit(0);
}
