#include "shuzagram/net/http_client.hpp"

#include <sys/socket.h>
#include <sys/time.h>

#include <algorithm>
#include <cctype>
#include <cstdint>

#include "shuzagram/net/tcp_socket.hpp"

namespace shuzagram::net {
namespace {

struct ParsedUrl {
    std::string host;
    std::uint16_t port = 80;
    std::string path;
};

ParsedUrl ParseHttpUrl(const std::string& url) {
    constexpr const char* kPrefix = "http://";
    if (url.rfind(kPrefix, 0) != 0) {
        throw HttpError("only plain http:// URLs are supported: " + url);
    }
    const std::string rest = url.substr(std::string(kPrefix).size());
    const auto slash = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    ParsedUrl parsed;
    parsed.path = slash == std::string::npos ? "/" : rest.substr(slash);
    if (authority.empty()) throw HttpError("URL has no host: " + url);

    const auto colon = authority.rfind(':');
    if (colon == std::string::npos) {
        parsed.host = authority;
    } else {
        parsed.host = authority.substr(0, colon);
        try {
            const int port = std::stoi(authority.substr(colon + 1));
            if (port <= 0 || port > 65535) throw std::out_of_range("port");
            parsed.port = static_cast<std::uint16_t>(port);
        } catch (const std::exception&) {
            throw HttpError("invalid port in URL: " + url);
        }
    }
    return parsed;
}

void SetSocketTimeout(int fd, std::chrono::milliseconds timeout) {
    struct timeval tv {};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

HttpResponse HttpPost(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                       const std::string& body, std::chrono::milliseconds timeout) {
    const ParsedUrl parsed = ParseHttpUrl(url);

    TcpSocket socket = [&] {
        try {
            return TcpSocket::Connect(parsed.host, parsed.port);
        } catch (const SocketError& e) {
            throw HttpError(std::string("connect failed: ") + e.what());
        }
    }();
    SetSocketTimeout(socket.fd(), timeout);

    std::string request = "POST " + parsed.path + " HTTP/1.1\r\n";
    request += "Host: " + parsed.host + "\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    request += "Connection: close\r\n";
    for (const auto& [name, value] : headers) {
        request += name + ": " + value + "\r\n";
    }
    request += "\r\n";
    request += body;

    try {
        socket.WriteAll(reinterpret_cast<const std::uint8_t*>(request.data()), request.size());
    } catch (const std::exception& e) {
        throw HttpError(std::string("send failed: ") + e.what());
    }

    // Read the status line + headers one byte at a time until the blank
    // line that terminates them. Payloads here are a handful of bytes (one
    // JSON acknowledgement), so the extra syscalls this costs don't matter
    // -- the same tradeoff TLBuffer's own doc comment already makes for
    // small, infrequent messages.
    std::string head;
    try {
        std::uint8_t byte = 0;
        while (head.size() < 4 || head.compare(head.size() - 4, 4, "\r\n\r\n") != 0) {
            socket.ReadExact(&byte, 1);
            head.push_back(static_cast<char>(byte));
            if (head.size() > 64 * 1024) throw HttpError("response headers too large");
        }
    } catch (const ConnectionClosedError&) {
        throw HttpError("connection closed before headers completed");
    } catch (const std::exception& e) {
        if (dynamic_cast<const HttpError*>(&e)) throw;
        throw HttpError(std::string("read failed: ") + e.what());
    }

    const auto first_line_end = head.find("\r\n");
    if (first_line_end == std::string::npos) throw HttpError("malformed HTTP response: no status line");
    const std::string status_line = head.substr(0, first_line_end);
    const auto sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) throw HttpError("malformed HTTP status line: " + status_line);
    int status = 0;
    try {
        status = std::stoi(status_line.substr(sp1 + 1, 3));
    } catch (const std::exception&) {
        throw HttpError("malformed HTTP status code: " + status_line);
    }

    std::size_t content_length = 0;
    bool has_content_length = false;
    std::size_t pos = first_line_end + 2;
    while (pos < head.size()) {
        const auto line_end = head.find("\r\n", pos);
        if (line_end == std::string::npos || line_end == pos) break;
        const std::string line = head.substr(pos, line_end - pos);
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string name = ToLowerAscii(line.substr(0, colon));
            if (name == "content-length") {
                auto value = line.substr(colon + 1);
                const auto first = value.find_first_not_of(' ');
                if (first != std::string::npos) {
                    try {
                        content_length = static_cast<std::size_t>(std::stoul(value.substr(first)));
                        has_content_length = true;
                    } catch (const std::exception&) {
                        // Malformed Content-Length: treat as absent (body read as empty
                        // below) rather than failing the whole response.
                    }
                }
            }
        }
        pos = line_end + 2;
    }

    HttpResponse response;
    response.status = status;
    if (has_content_length && content_length > 0) {
        if (content_length > 1024 * 1024) throw HttpError("response body too large");
        response.body.resize(content_length);
        try {
            socket.ReadExact(reinterpret_cast<std::uint8_t*>(response.body.data()), content_length);
        } catch (const std::exception& e) {
            throw HttpError(std::string("read body failed: ") + e.what());
        }
    }
    // No Content-Length (and not a case this client needs to chunk-decode):
    // body is treated as empty, matching every real response this client
    // actually talks to (numbot/otpwebhook-example always set it).
    return response;
}

} // namespace shuzagram::net
