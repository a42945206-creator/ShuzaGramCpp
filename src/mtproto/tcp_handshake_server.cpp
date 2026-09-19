#include "shuzagram/mtproto/tcp_handshake_server.hpp"

#include <optional>
#include <thread>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/session.hpp"
#include "shuzagram/mtproto/transport/detect_transport.hpp"

namespace shuzagram::mtproto {

TcpHandshakeServer::TcpHandshakeServer(const std::string& bind_address, std::uint16_t port, crypto::RsaPrivateKey key,
                                        const RpcHandlerRegistry* rpc_registry)
    : listener_(bind_address, port), key_(std::move(key)), rpc_registry_(rpc_registry) {}

void TcpHandshakeServer::Run(const SuccessHandler& on_success, const FailureHandler& on_failure) {
    // Polls with a short timeout rather than blocking in Accept()
    // indefinitely, so Stop() (which just flips stopping_) is noticed
    // promptly and reliably -- see AcceptWithTimeout's doc comment for why
    // this loop doesn't just close the listening fd from another thread
    // instead.
    constexpr auto kPollInterval = std::chrono::milliseconds(200);
    while (!stopping_.load()) {
        std::optional<net::TcpSocket> socket = listener_.AcceptWithTimeout(kPollInterval);
        if (!socket) continue;

        // One detached thread per connection: simple and adequate for this
        // round's goal (prove the wiring works), not a production-grade
        // connection-handling model. See NOTES/tcp-wiring-plan.md.
        std::thread([this, socket = std::move(*socket), on_success, on_failure]() mutable {
            try {
                auto reader = socket.Reader();
                auto writer = socket.Writer();
                // DetectTransport (not the bare DetectCodec this project
                // used before this round) transparently also accepts
                // obfuscated2 -- what a real client sends by default -- see
                // NOTES/obfuscated2-transport-plan.md. No MTProxy secret:
                // this server is a direct DC, not a proxy hop.
                transport::DetectedTransport detected = transport::DetectTransport(reader, writer);
                ServerExchange exchange(key_);
                const ServerExchangeResult result = exchange.Run(
                    [&] { return detected.codec->Read(detected.read); },
                    [&](const std::vector<std::uint8_t>& frame) { detected.codec->Write(detected.write, frame); });
                if (on_success) on_success(result);

                if (!rpc_registry_) return; // old behavior: close right after the handshake

                // Continue serving this same connection: read encrypted
                // frames, dispatch them through MtprotoSession, write back
                // whatever replies it produces, until the connection ends.
                // session_id starts at 0 -- MtprotoSession adopts the
                // client's real one from the first decrypted message (see
                // its own header comment).
                MtprotoSession session(result.auth_key, /*session_id=*/0, result.server_salt, crypto::Side::kServer,
                                       rpc_registry_);
                for (;;) {
                    const auto frame = detected.codec->Read(detected.read);
                    TLBuffer frame_buf;
                    frame_buf.buf = frame;
                    crypto::EncryptedMessage encrypted;
                    encrypted.Decode(frame_buf);

                    const auto replies = session.HandleEncrypted(encrypted);
                    for (const auto& reply : replies) {
                        TLBuffer out;
                        reply.Encode(out);
                        detected.codec->Write(detected.write, out.buf);
                    }
                }
            } catch (const std::exception& e) {
                if (on_failure) on_failure(e.what());
            } catch (...) {
                if (on_failure) on_failure("unknown error");
            }
        }).detach();
    }
}

void TcpHandshakeServer::Stop() {
    // Just the flag: Run()'s poll loop checks it at least once per
    // kPollInterval, so this returns almost immediately without needing to
    // touch the listening socket while Run() might still be polling on it
    // concurrently (see AcceptWithTimeout's doc comment for why that would
    // be unsafe). The listener itself closes when this object is
    // destroyed.
    stopping_.store(true);
}

} // namespace shuzagram::mtproto
