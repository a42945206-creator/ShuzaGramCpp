// Checks for otpdelivery::Signature/WebhookSender.
//
// TestSignatureMatchesIndependentReference cross-checks against a value
// computed OUTSIDE this codebase:
//   printf '%s' '1700000000.{"code":"12345"}' | openssl dgst -sha256 -hmac 'testsecret'
//   => 197bf7ba5db7be5c0bb0fa67726ed9013c7b3cd47c54ac5d6f9fa9c53ac37170
// same discipline as mtproto_srp_test.cpp's use of the official gotd/td
// test vector: this isolates "is the HMAC construction right" from "does
// Deliver() plumb it through correctly" (the latter is covered by
// TestDeliverSendsSignedRequestAndParsesAcceptance below, which recomputes
// the signature from what the server actually received and checks it
// against the header the client actually sent -- a self-consistency check,
// not a replacement for the fixed vector).

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include "shuzagram/net/tcp_listener.hpp"
#include "shuzagram/otpdelivery/signature.hpp"
#include "shuzagram/otpdelivery/webhook_sender.hpp"

namespace {

using namespace shuzagram;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

struct CapturedRequest {
    std::string headers;
    std::string body;
};

CapturedRequest ReadRawRequest(net::TcpSocket& socket) {
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
    if (content_length > 0) socket.ReadExact(reinterpret_cast<std::uint8_t*>(body.data()), content_length);
    return {head, body};
}

std::string HeaderValue(const std::string& headers, const std::string& name) {
    const auto pos = headers.find(name + ": ");
    if (pos == std::string::npos) return "";
    const auto start = pos + name.size() + 2;
    const auto end = headers.find("\r\n", start);
    return headers.substr(start, end - start);
}

void TestSignatureMatchesIndependentReference() {
    const std::string sig = otpdelivery::Signature("testsecret", "1700000000", R"({"code":"12345"})");
    Check(sig == "sha256=197bf7ba5db7be5c0bb0fa67726ed9013c7b3cd47c54ac5d6f9fa9c53ac37170",
          "HMAC-SHA256 signature matches the independently computed (openssl dgst) reference value");
}

void TestNewDeliveryIDHasExpectedShapeAndIsRandom() {
    const auto a = otpdelivery::NewDeliveryID();
    const auto b = otpdelivery::NewDeliveryID();
    Check(a.rfind("otp_", 0) == 0, "delivery id starts with the otp_ prefix");
    Check(a.size() == 4 + 32, "delivery id is 'otp_' + 16 random bytes as hex (32 chars)");
    Check(a != b, "two calls produce different ids");
}

void TestDeliverSendsSignedRequestAndParsesAcceptance() {
    net::TcpListener listener("127.0.0.1", 0);
    CapturedRequest captured;

    std::thread server([&] {
        auto socket = listener.Accept();
        captured = ReadRawRequest(socket);
        const std::string body = R"({"accepted":true,"message_id":"numbot_abc"})";
        const std::string raw = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        socket.WriteAll(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
    });

    otpdelivery::WebhookSender::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/otp";
    config.secret = "testsecret";
    config.timeout = std::chrono::seconds(5);
    otpdelivery::WebhookSender sender(config);

    otpdelivery::Request request;
    request.delivery_id = "otp_test123";
    request.purpose = "login_sms";
    request.channel = "sms";
    request.recipient = "+15550001111";
    request.code = "54321";
    request.expires_at = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count() +
                          300;

    const auto result = sender.Deliver(request);
    server.join();

    Check(result.provider_message_id == "numbot_abc", "the provider's message_id is returned on acceptance");
    Check(captured.body.find(R"("delivery_id":"otp_test123")") != std::string::npos, "delivery_id is in the body");
    Check(captured.body.find(R"("purpose":"login_sms")") != std::string::npos, "purpose is in the body");
    Check(captured.body.find(R"("channel":"sms")") != std::string::npos, "channel is in the body");
    Check(captured.body.find(R"("recipient":"+15550001111")") != std::string::npos, "recipient is in the body");
    Check(captured.body.find(R"("code":"54321")") != std::string::npos, "code is in the body");
    Check(captured.body.find(R"("version":"1")") != std::string::npos, "version is \"1\"");

    Check(HeaderValue(captured.headers, "Idempotency-Key") == "otp_test123",
          "Idempotency-Key header equals delivery_id");
    const std::string timestamp = HeaderValue(captured.headers, "X-Telesrv-Timestamp");
    Check(!timestamp.empty(), "X-Telesrv-Timestamp header is present");
    const std::string expected_sig = otpdelivery::Signature("testsecret", timestamp, captured.body);
    Check(HeaderValue(captured.headers, "X-Telesrv-Signature") == expected_sig,
          "the signature header matches recomputing Signature() over the timestamp actually sent and the body "
          "actually received");
}

void TestDeliverThrowsOnRejection() {
    net::TcpListener listener("127.0.0.1", 0);
    std::thread server([&] {
        auto socket = listener.Accept();
        ReadRawRequest(socket);
        const std::string body = R"({"accepted":false,"error_code":"RECIPIENT_UNKNOWN"})";
        const std::string raw =
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        socket.WriteAll(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
    });

    otpdelivery::WebhookSender::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/otp";
    config.timeout = std::chrono::seconds(5);
    otpdelivery::WebhookSender sender(config);

    bool threw = false;
    try {
        sender.Deliver(otpdelivery::Request{"id", "login_sms", "sms", "+1", "12345", 0});
    } catch (const otpdelivery::DeliveryFailedError&) {
        threw = true;
    }
    server.join();
    Check(threw, "a non-2xx status throws DeliveryFailedError");
}

void TestDeliverThrowsWhenNothingIsListening() {
    net::TcpListener listener("127.0.0.1", 0);
    const auto port = listener.Port();
    listener.Close();

    otpdelivery::WebhookSender::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(port) + "/otp";
    config.timeout = std::chrono::seconds(1);
    otpdelivery::WebhookSender sender(config);

    bool threw = false;
    try {
        sender.Deliver(otpdelivery::Request{"id", "login_sms", "sms", "+1", "12345", 0});
    } catch (const otpdelivery::DeliveryFailedError&) {
        threw = true;
    }
    Check(threw, "an unreachable webhook throws DeliveryFailedError, matching the OutcomeUnknown treatment");
}

} // namespace

int main() {
    TestSignatureMatchesIndependentReference();
    TestNewDeliveryIDHasExpectedShapeAndIsRandom();
    TestDeliverSendsSignedRequestAndParsesAcceptance();
    TestDeliverThrowsOnRejection();
    TestDeliverThrowsWhenNothingIsListening();
    if (g_failures == 0) {
        std::printf("all otp webhook tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d otp webhook test(s) failed\n", g_failures);
    return 1;
}
