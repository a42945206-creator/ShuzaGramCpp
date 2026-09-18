#include "shuzagram/net/tcp_socket.hpp"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace shuzagram::net {

namespace {
[[noreturn]] void ThrowErrno(const std::string& what) {
    throw SocketError(what + ": " + std::strerror(errno));
}
} // namespace

TcpSocket::TcpSocket(int fd) : fd_(fd) {}

TcpSocket::~TcpSocket() { Close(); }

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        Close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void TcpSocket::Close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

TcpSocket TcpSocket::Connect(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    const std::string port_str = std::to_string(port);
    const int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0) throw SocketError(std::string("resolve ") + host + ": " + gai_strerror(rc));

    int fd = -1;
    for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(result);
    if (fd < 0) throw SocketError("connect to " + host + ":" + port_str + " failed");

    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return TcpSocket(fd);
}

void TcpSocket::ReadExact(std::uint8_t* buf, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        const ssize_t n = ::recv(fd_, buf + off, len - off, 0);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) throw ConnectionClosedError();
        if (errno == EINTR) continue;
        ThrowErrno("recv");
    }
}

void TcpSocket::WriteAll(const std::uint8_t* buf, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        // MSG_NOSIGNAL: writing to a peer that already closed its end
        // raises SIGPIPE by default, which kills the process unless every
        // caller remembers to block/ignore it -- ask the kernel to just
        // fail the call with EPIPE instead.
        const ssize_t n = ::send(fd_, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        ThrowErrno("send");
    }
}

mtproto::transport::ReadExact TcpSocket::Reader() {
    return [this](std::uint8_t* buf, std::size_t len) { ReadExact(buf, len); };
}

mtproto::transport::WriteBytes TcpSocket::Writer() {
    return [this](const std::uint8_t* buf, std::size_t len) { WriteAll(buf, len); };
}

} // namespace shuzagram::net
