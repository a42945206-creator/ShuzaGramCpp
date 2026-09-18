#include "shuzagram/net/tcp_listener.hpp"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace shuzagram::net {

namespace {
[[noreturn]] void ThrowErrno(const std::string& what) {
    throw SocketError(what + ": " + std::strerror(errno));
}
} // namespace

TcpListener::TcpListener(const std::string& bind_address, std::uint16_t port, int backlog) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) ThrowErrno("socket");

    const int one = 1;
    // So restarting the server right after it exits doesn't fail to bind
    // with "address already in use" while the OS still holds the old
    // socket in TIME_WAIT.
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_address.empty() || bind_address == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (::inet_pton(AF_INET, bind_address.c_str(), &addr.sin_addr) != 1) {
        ::close(fd_);
        throw SocketError("invalid IPv4 bind address: " + bind_address);
    }

    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(fd_);
        throw SocketError("bind " + bind_address + ":" + std::to_string(port) + ": " + msg);
    }
    if (::listen(fd_, backlog) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(fd_);
        throw SocketError("listen: " + msg);
    }

    sockaddr_in bound{};
    socklen_t bound_len = sizeof(bound);
    if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&bound), &bound_len) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(fd_);
        throw SocketError("getsockname: " + msg);
    }
    port_ = ntohs(bound.sin_port);
}

TcpListener::~TcpListener() { Close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept : fd_(other.fd_), port_(other.port_) { other.fd_ = -1; }

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
    if (this != &other) {
        Close();
        fd_ = other.fd_;
        port_ = other.port_;
        other.fd_ = -1;
    }
    return *this;
}

void TcpListener::Close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

namespace {
TcpSocket FinishAccept(int client_fd) {
    const int one = 1;
    ::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return TcpSocket(client_fd);
}
} // namespace

TcpSocket TcpListener::Accept() {
    const int client_fd = ::accept(fd_, nullptr, nullptr);
    if (client_fd < 0) ThrowErrno("accept");
    return FinishAccept(client_fd);
}

std::optional<TcpSocket> TcpListener::AcceptWithTimeout(std::chrono::milliseconds timeout) {
    pollfd pfd{};
    pfd.fd = fd_;
    pfd.events = POLLIN;

    const int rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rc < 0) {
        if (errno == EINTR) return std::nullopt;
        ThrowErrno("poll");
    }
    if (rc == 0) return std::nullopt; // timed out, no pending connection

    const int client_fd = ::accept(fd_, nullptr, nullptr);
    if (client_fd < 0) {
        // A connection that arrived and was reset before accept() got to it
        // is routine under load, not a listener failure -- treat it like a
        // timeout rather than propagating.
        if (errno == ECONNABORTED || errno == EAGAIN || errno == EWOULDBLOCK) return std::nullopt;
        ThrowErrno("accept");
    }
    return FinishAccept(client_fd);
}

} // namespace shuzagram::net
