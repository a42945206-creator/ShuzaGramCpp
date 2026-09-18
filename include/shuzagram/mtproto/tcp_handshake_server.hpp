#pragma once

#include <atomic>
#include <functional>
#include <string>

#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/server_exchange.hpp"
#include "shuzagram/net/tcp_listener.hpp"

// Wires TcpListener + transport::DetectCodec + ServerExchange together: the
// first piece of this project that actually listens on a real TCP port.
// One thread per accepted connection (a real epoll/async-IO event loop is a
// deliberately separate, later piece -- see NOTES/tcp-wiring-plan.md).
//
// Deliberately independent of the store:: layer: what happens with a
// completed handshake (persisting the auth_key, and everything after) is
// the caller's job via the result callback, not this class's -- so it can
// be exercised in tests without a live Postgres, and so cmd/shuzagram_server
// is the only place that wires the two together.
namespace shuzagram::mtproto {

class TcpHandshakeServer {
public:
    TcpHandshakeServer(const std::string& bind_address, std::uint16_t port, crypto::RsaPrivateKey key);

    [[nodiscard]] std::uint16_t Port() const { return listener_.Port(); }

    // Called (from a connection's own worker thread -- may be called
    // concurrently from several threads for several connections at once,
    // callers must be thread-safe) once a connection's handshake succeeds.
    using SuccessHandler = std::function<void(const ServerExchangeResult&)>;
    // Called on any failure (bad transport, failed handshake, I/O error).
    // Purely informational -- the connection is closed either way.
    using FailureHandler = std::function<void(const std::string& what)>;

    // Blocks, accepting connections and spawning one detached worker thread
    // per connection, until Stop() is called from another thread.
    void Run(const SuccessHandler& on_success, const FailureHandler& on_failure = {});

    // Requests that Run()'s accept loop exit; returns immediately (does not
    // wait for Run() to actually return -- join whatever thread is running
    // it for that). Safe to call from a different thread than the one
    // running Run(). Run() notices within one poll interval (currently
    // 200ms), not instantly -- see tcp_handshake_server.cpp.
    void Stop();

private:
    net::TcpListener listener_;
    crypto::RsaPrivateKey key_;
    std::atomic<bool> stopping_{false};
};

} // namespace shuzagram::mtproto
