#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

// Faithful, scoped port of internal/otpdelivery (the Sender interface) and
// internal/otpdelivery/webhook (its HTTP implementation) -- the exact "OTP
// Webhook v1" protocol the real ShuzaGram Go server speaks, and the SAME
// protocol the already-deployed `numbot` container implements on its
// receiving side (see NOTES/otp-webhook-delivery-plan.md). Pointing this
// port's SHUZAGRAM_OTP_WEBHOOK_URL/SECRET at that numbot instance delivers
// a real login code to a real Telegram user.
namespace shuzagram::otpdelivery {

class DeliveryFailedError : public std::runtime_error {
public:
    explicit DeliveryFailedError(const std::string& what) : std::runtime_error(what) {}
};

struct Request {
    std::string delivery_id;
    std::string purpose;   // e.g. "login_sms" -- see otpdelivery.Purpose in the Go source
    std::string channel;   // e.g. "sms" -- see otpdelivery.Channel in the Go source
    std::string recipient; // phone number, normalized the same way auth::SendCode already does
    std::string code;
    std::int64_t expires_at = 0; // Unix seconds
};

struct Result {
    std::string provider_message_id; // empty if the provider didn't return one
};

class WebhookSender {
public:
    struct Config {
        std::string url;
        std::string secret;
        std::chrono::milliseconds timeout{5000};
    };

    explicit WebhookSender(Config config) : config_(std::move(config)) {}

    // Mirrors webhook.Sender.Deliver's success/failure split, minus its
    // granular RejectedError/OutcomeUnknownError distinction (this port has
    // no retry logic to make that distinction useful yet -- see the NOTES
    // file). Throws DeliveryFailedError on ANY non-accepted outcome: network
    // failure, non-2xx, or a 2xx body that isn't {"accepted":true}.
    Result Deliver(const Request& request) const;

private:
    Config config_;
};

// Mirrors otpdelivery.NewDeliveryID: "otp_" + 16 random bytes as hex.
std::string NewDeliveryID();

} // namespace shuzagram::otpdelivery
