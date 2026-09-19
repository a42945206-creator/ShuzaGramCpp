#include "shuzagram/otpdelivery/webhook_sender.hpp"

#include <ctime>
#include <nlohmann/json.hpp>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/net/http_client.hpp"
#include "shuzagram/otpdelivery/signature.hpp"

namespace shuzagram::otpdelivery {
namespace {

// time.RFC3339 with no fractional seconds, always UTC -- matches
// delivery.ExpiresAt.UTC().Format(time.RFC3339).
std::string FormatRfc3339Utc(std::int64_t unix_seconds) {
    const std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace

std::string NewDeliveryID() {
    const auto raw = mtproto::crypto::SystemRandomBytes(16);
    return "otp_" + HexEncode(raw.data(), raw.size());
}

Result WebhookSender::Deliver(const Request& request) const {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    std::int64_t expires_in = request.expires_at - now;
    if (expires_in < 1) expires_in = 1;

    nlohmann::json j;
    j["version"] = "1";
    j["delivery_id"] = request.delivery_id;
    j["purpose"] = request.purpose;
    j["channel"] = request.channel;
    j["recipient"] = request.recipient;
    j["code"] = request.code;
    j["expires_at"] = FormatRfc3339Utc(request.expires_at);
    j["expires_in"] = expires_in;
    const std::string body = j.dump();

    const std::string timestamp = std::to_string(now);
    std::vector<std::pair<std::string, std::string>> headers = {
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
        {"Idempotency-Key", request.delivery_id},
        {"X-Telesrv-Timestamp", timestamp},
    };
    if (!config_.secret.empty()) {
        headers.emplace_back("X-Telesrv-Signature", Signature(config_.secret, timestamp, body));
    }

    net::HttpResponse response;
    try {
        response = net::HttpPost(config_.url, headers, body, config_.timeout);
    } catch (const net::HttpError& e) {
        throw DeliveryFailedError(std::string("otp webhook delivery outcome unknown: ") + e.what());
    }

    if (response.status == 204) {
        return Result{};
    }
    if (response.status < 200 || response.status >= 300) {
        throw DeliveryFailedError("otp webhook rejected the delivery (status " + std::to_string(response.status) +
                                   "): " + response.body);
    }
    const auto parsed = nlohmann::json::parse(response.body, nullptr, /*allow_exceptions=*/false);
    if (parsed.is_discarded() || !parsed.is_object() || !parsed.contains("accepted") ||
        !parsed["accepted"].is_boolean()) {
        throw DeliveryFailedError("otp webhook returned a 2xx response with no valid \"accepted\" field");
    }
    if (!parsed["accepted"].get<bool>()) {
        const std::string error_code = parsed.value("error_code", std::string());
        throw DeliveryFailedError("otp webhook did not accept the delivery: " + error_code);
    }
    Result result;
    result.provider_message_id = parsed.value("message_id", std::string());
    return result;
}

} // namespace shuzagram::otpdelivery
