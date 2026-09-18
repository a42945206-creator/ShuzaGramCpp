#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "shuzagram/net/tcp_socket.hpp"

namespace shuzagram::net {

class TcpListener {
public:
    // Binds and starts listening immediately (throws SocketError on
    // failure). Passing port 0 asks the OS to pick a free port -- call
    // Port() afterward to find out which one; used by tests so they never
    // fight over a fixed port.
    TcpListener(const std::string& bind_address, std::uint16_t port, int backlog = 128);
    ~TcpListener();

    TcpListener(TcpListener&&) noexcept;
    TcpListener& operator=(TcpListener&&) noexcept;
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    // Blocks until a client connects. Throws SocketError on failure.
    [[nodiscard]] TcpSocket Accept();

    // Waits up to timeout for a connection; returns std::nullopt on
    // timeout instead of blocking indefinitely. This -- not closing the fd
    // from another thread -- is the reliable way to make an accept loop
    // stoppable: POSIX does not guarantee that close()-ing a file
    // descriptor another thread is blocked in accept() on actually
    // unblocks it (confirmed the hard way: it works often enough to pass
    // by luck and hangs the rest of the time). See
    // NOTES/tcp-wiring-plan.md.
    [[nodiscard]] std::optional<TcpSocket> AcceptWithTimeout(std::chrono::milliseconds timeout);

    // The actual bound port -- only interesting when the constructor was
    // given port 0.
    [[nodiscard]] std::uint16_t Port() const { return port_; }

    // Closes the listening socket. Only meaningful once nothing is blocked
    // in Accept()/AcceptWithTimeout() anymore -- use AcceptWithTimeout's
    // polling loop to stop cleanly first (see its doc comment), then call
    // this to release the fd/port.
    void Close() noexcept;

private:
    int fd_;
    std::uint16_t port_;
};

} // namespace shuzagram::net
