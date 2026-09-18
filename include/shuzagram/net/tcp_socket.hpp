#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include "shuzagram/mtproto/transport/codec.hpp"

// A thin RAII wrapper over a POSIX TCP socket file descriptor, exposing
// exactly the two primitives shuzagram::mtproto needs
// (mtproto::transport::ReadExact/WriteBytes) so the already-built and
// already-tested handshake/transport-framing code can run over a real
// connection instead of the in-memory pipes the test suite uses. Linux/
// POSIX only (no Windows sockets) -- matches this project's deployment
// target. See NOTES/tcp-wiring-plan.md.
namespace shuzagram::net {

class SocketError : public std::runtime_error {
public:
    explicit SocketError(const std::string& what) : std::runtime_error(what) {}
};

// Thrown by ReadExact when the peer closes the connection (recv() returns
// 0) before the requested number of bytes arrived -- distinct from a real
// socket error, since an orderly peer disconnect is an expected event a
// connection handler needs to tell apart from "something is broken".
class ConnectionClosedError : public std::runtime_error {
public:
    ConnectionClosedError() : std::runtime_error("connection closed by peer") {}
};

class TcpSocket {
public:
    // Takes ownership of an already-connected/accepted file descriptor.
    explicit TcpSocket(int fd);
    ~TcpSocket();

    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    // Connects to host:port (host may be a dotted IPv4 address or a
    // hostname resolved via getaddrinfo). Throws SocketError on failure.
    static TcpSocket Connect(const std::string& host, std::uint16_t port);

    // Blocks until exactly len bytes have been read into buf. Throws
    // ConnectionClosedError on an orderly peer close, SocketError on any
    // other failure.
    void ReadExact(std::uint8_t* buf, std::size_t len);
    // Blocks until exactly len bytes have been written. Throws SocketError
    // on failure (including a peer-reset connection).
    void WriteAll(const std::uint8_t* buf, std::size_t len);

    // Adapters matching shuzagram::mtproto::transport's callback types --
    // pass these directly to DetectCodec/Codec::Read/Codec::Write/
    // ServerExchange::Run.
    [[nodiscard]] mtproto::transport::ReadExact Reader();
    [[nodiscard]] mtproto::transport::WriteBytes Writer();

    void Close() noexcept;
    [[nodiscard]] int fd() const { return fd_; }

private:
    int fd_;
};

} // namespace shuzagram::net
