#pragma once

#include <openssl/hmac.h>

#include <cstdint>
#include <string>

// The "OTP Webhook v1" request signature: HMAC-SHA256 over
// timestamp + "." + body, hex-encoded, prefixed "sha256=". Copied from
// internal/otpdelivery/webhook/sender.go's signature() function. Split out
// of webhook_sender.cpp so tests can check it against an independently
// computed reference value (`openssl dgst -sha256 -hmac <secret>` on
// `<timestamp>.<body>`), the same discipline used for this project's other
// crypto primitives (see mtproto_srp_test.cpp).
namespace shuzagram::otpdelivery {

inline std::string HexEncode(const std::uint8_t* data, std::size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

inline std::string Signature(const std::string& secret, const std::string& timestamp, const std::string& body) {
    std::string message = timestamp;
    message += '.';
    message += body;

    std::uint8_t out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const std::uint8_t*>(message.data()), message.size(), out, &out_len);
    return "sha256=" + HexEncode(out, out_len);
}

} // namespace shuzagram::otpdelivery
