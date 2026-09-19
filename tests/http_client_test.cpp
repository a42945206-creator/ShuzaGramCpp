// Real end-to-end checks for net::HttpPost against a hand-rolled HTTP
// server over a real loopback TCP socket (same discipline as
// net_tcp_rpc_test.cpp: client and server in one process, real syscalls,
// not an in-memory pipe).

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include "shuzagram/net/http_client.hpp"
#include "shuzagram/net/tcp_listener.hpp"

namespace {

using namespace shuzagram;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// Reads one HTTP/1.1 request off `socket` (headers via ReadExact(1) until
// "\r\n\r\n", body via Content-Length) and returns the raw request text
// (headers + body) so the test can assert on exactly what the client sent.
std::string ReadRawRequest(net::TcpSocket& socket) {
    std::string head;
    std::uint8_t byte = 0;
    while (head.size() < 4 || head.compare(head.size() - 4, 4, "\r\n\r\n") != 0) {
        socket.ReadExact(&byte, 1);
        head.push_back(static_cast<char>(byte));
    }
    std::size_t content_length = 0;
    const auto cl_pos = head.find("Content-Length:");
    if (cl_pos != std::string::npos) {
        content_length = static_cast<std::size_t>(std::stoul(head.substr(cl_pos + 16)));
    }
    std::string body(content_length, '\0');
    if (content_length > 0) {
        socket.ReadExact(reinterpret_cast<std::uint8_t*>(body.data()), content_length);
    }
    return head + body;
}

void WriteRawResponse(net::TcpSocket& socket, const std::string& raw) {
    socket.WriteAll(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
}

void TestPostSendsExpectedRequestAndParsesResponse() {
    net::TcpListener listener("127.0.0.1", 0);
    std::string captured_request;

    std::thread server([&] {
        auto socket = listener.Accept();
        captured_request = ReadRawRequest(socket);
        const std::string body = R"({"accepted":true,"message_id":"abc"})";
        WriteRawResponse(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                                      std::to_string(body.size()) + "\r\n\r\n" + body);
    });

    const std::string url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/v1/otp/deliveries";
    const auto response = net::HttpPost(url, {{"X-Custom", "hello"}}, R"({"code":"12345"})", std::chrono::seconds(5));
    server.join();

    Check(response.status == 200, "status 200 is parsed correctly");
    Check(response.body == R"({"accepted":true,"message_id":"abc"})", "body is read using Content-Length");
    Check(captured_request.find("POST /v1/otp/deliveries HTTP/1.1") == 0, "request line has the right method/path");
    Check(captured_request.find("Host: 127.0.0.1") != std::string::npos, "Host header is sent");
    Check(captured_request.find("X-Custom: hello") != std::string::npos, "caller-supplied headers are sent");
    Check(captured_request.find(R"({"code":"12345"})") != std::string::npos, "body is sent verbatim");
}

void TestNon2xxStatusIsStillParsed() {
    net::TcpListener listener("127.0.0.1", 0);
    std::thread server([&] {
        auto socket = listener.Accept();
        ReadRawRequest(socket);
        const std::string body = R"({"accepted":false,"error_code":"RECIPIENT_UNKNOWN"})";
        WriteRawResponse(socket, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + std::to_string(body.size()) +
                                      "\r\n\r\n" + body);
    });
    const std::string url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/otp";
    const auto response = net::HttpPost(url, {}, "{}", std::chrono::seconds(5));
    server.join();
    Check(response.status == 502, "a non-2xx status is returned, not thrown, so the caller can inspect it");
    Check(response.body.find("RECIPIENT_UNKNOWN") != std::string::npos, "non-2xx body is still readable");
}

void TestNoBodyWithoutContentLength() {
    net::TcpListener listener("127.0.0.1", 0);
    std::thread server([&] {
        auto socket = listener.Accept();
        ReadRawRequest(socket);
        WriteRawResponse(socket, "HTTP/1.1 204 No Content\r\n\r\n");
    });
    const std::string url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/otp";
    const auto response = net::HttpPost(url, {}, "{}", std::chrono::seconds(5));
    server.join();
    Check(response.status == 204, "204 is parsed");
    Check(response.body.empty(), "no Content-Length -> empty body, not a hang waiting for more bytes");
}

void TestRejectsNonHttpUrl() {
    bool threw = false;
    try {
        net::HttpPost("https://example.com/", {}, "{}", std::chrono::seconds(1));
    } catch (const net::HttpError&) {
        threw = true;
    }
    Check(threw, "an https:// URL is rejected (no TLS support), not silently misparsed");
}

void TestConnectionRefusedThrows() {
    // Nothing is listening on this port (freshly bound-then-closed, so the
    // OS won't hand it to anything else in the meantime).
    net::TcpListener listener("127.0.0.1", 0);
    const auto port = listener.Port();
    listener.Close();

    bool threw = false;
    try {
        net::HttpPost("http://127.0.0.1:" + std::to_string(port) + "/", {}, "{}", std::chrono::seconds(1));
    } catch (const net::HttpError&) {
        threw = true;
    }
    Check(threw, "a refused connection throws HttpError, not a raw socket exception leaking out");
}

} // namespace

int main() {
    TestPostSendsExpectedRequestAndParsesResponse();
    TestNon2xxStatusIsStillParsed();
    TestNoBodyWithoutContentLength();
    TestRejectsNonHttpUrl();
    TestConnectionRefusedThrows();
    if (g_failures == 0) {
        std::printf("all http client tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d http client test(s) failed\n", g_failures);
    return 1;
}
