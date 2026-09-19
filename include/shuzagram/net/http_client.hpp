#pragma once

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// A minimal, blocking HTTP/1.1 client -- just enough to POST a small JSON
// body and read back a small JSON response, which is all
// otpdelivery::WebhookSender needs. Deliberately NOT a general-purpose HTTP
// library: plain http:// only (no TLS -- see NOTES/otp-webhook-delivery-plan.md
// for why that's an acceptable scope cut for this deployment shape), no
// chunked transfer-encoding, no redirects, no connection reuse, no
// keep-alive (every request is Connection: close).
namespace shuzagram::net {

class HttpError : public std::runtime_error {
public:
    explicit HttpError(const std::string& what) : std::runtime_error(what) {}
};

struct HttpResponse {
    int status = 0;
    std::string body;
};

// url must be an absolute http:// URL (http://host[:port]/path...). Throws
// HttpError on any parse/connect/timeout/protocol failure -- there is no
// partial-success return value, matching how the caller (otpdelivery)
// already treats "didn't get a clean response" as a delivery failure.
HttpResponse HttpPost(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                       const std::string& body, std::chrono::milliseconds timeout);

} // namespace shuzagram::net
