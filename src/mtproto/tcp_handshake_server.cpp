#include "shuzagram/mtproto/tcp_handshake_server.hpp"

#include <optional>
#include <thread>

#include "shuzagram/mtproto/transport/detect_codec.hpp"

namespace shuzagram::mtproto {

TcpHandshakeServer::TcpHandshakeServer(const std::string& bind_address, std::uint16_t port, crypto::RsaPrivateKey key)
    : listener_(bind_address, port), key_(std::move(key)) {}

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
                transport::DetectedCodec detected = transport::DetectCodec(reader);
                ServerExchange exchange(key_);
                const ServerExchangeResult result = exchange.Run(
                    [&] { return detected.codec->Read(detected.read); },
                    [&](const std::vector<std::uint8_t>& frame) { detected.codec->Write(writer, frame); });
                if (on_success) on_success(result);
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
