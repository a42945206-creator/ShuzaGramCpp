#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <vector>

#include "shuzagram/mtproto/crypto/rsa.hpp"

// Port of (exchange.ServerExchange).Run (github.com/iamxvbaba/td,
// exchange/server_flow.go): the server side of MTProto's DH key exchange.
// See NOTES/transport-handshake-plan.md for the full piece-by-piece
// breakdown and what's deliberately deferred (temp-key PFS binding, the
// non-standard iOS p_q_inner_data_temp#3c6a84d4, transport framing).
namespace shuzagram::mtproto {

// Transport-level protocol error codes a failed exchange may need to
// report (proto/codec/errors.go). Not yet wired to an actual wire response
// in this slice -- ServerExchangeError just carries the code for whichever
// caller ends up owning that write.
inline constexpr std::int32_t kCodeAuthKeyNotFound = 404;
inline constexpr std::int32_t kCodeWrongDc = 444;

class ServerExchangeError : public std::runtime_error {
public:
    ServerExchangeError(std::int32_t code, const std::string& what) : std::runtime_error(what), code_(code) {}
    [[nodiscard]] std::int32_t code() const { return code_; }

private:
    std::int32_t code_;
};

struct ServerExchangeResult {
    std::array<std::uint8_t, 256> auth_key{};
    std::int64_t server_salt = 0;
};

// The server never generates its own pq/dh_prime randomly: this project
// (like the ShuzaGram production deployment it ports -- see
// internal/mtprotoedge/exchange_compat.go: compatServerRNG, and
// NOTES/transport-handshake-plan.md for why this isn't a bug to "fix" here)
// uses the same fixed pq and dh_prime as gotd/td's own TestServerRNG. Only
// the ephemeral DH exponent `a` (ServerExchange::GenerateGA) is genuinely
// random per connection -- that's the actual secret the exchange protects.
std::vector<std::uint8_t> FixedPq();
std::vector<std::uint8_t> FixedDhPrime();
inline constexpr int kDhGenerator = 3; // g, hardcoded in the Go source's Run(), not part of ServerRNG

// Reads and writes complete handshake message frames (already unwrapped
// from whatever transport framing wraps them -- abridged/intermediate/full
// framing is a separate, not-yet-ported piece). Read must block until a
// full frame is available; both may throw to abort the exchange.
using ReadFrame = std::function<std::vector<std::uint8_t>()>;
using WriteFrame = std::function<void(const std::vector<std::uint8_t>&)>;

class ServerExchange {
public:
    explicit ServerExchange(crypto::RsaPrivateKey key) : key_(std::move(key)) {}

    // Runs one complete handshake to completion (or throws). See
    // NOTES/transport-handshake-plan.md item 8 for the exact message
    // sequence.
    ServerExchangeResult Run(const ReadFrame& read, const WriteFrame& write);

private:
    crypto::RsaPrivateKey key_;
};

} // namespace shuzagram::mtproto
