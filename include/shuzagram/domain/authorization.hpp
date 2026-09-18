#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>

// Faithful port of internal/domain/authorization.go.
namespace shuzagram::domain {

// Authorization is one device authorization: the auth_key <-> user binding
// plus initConnection device info. auth_key is a protocol artifact;
// authorization is a business artifact, hence its independence from
// store::AuthKeyData.
struct Authorization {
    std::array<std::uint8_t, 8> auth_key_id{}; // native protocol auth_key_id; little-endian at the store boundary
    std::int64_t user_id = 0;
    std::int64_t hash = 0;
    // layer is the last supported protocol profile explicitly observed for
    // this auth key. It is a durable default for a new session, never an
    // instruction to rewrite an already-active session's own profile.
    int layer = 0;
    std::string device_model;
    std::string platform;
    std::string system_version;
    int api_id = 0;
    std::string app_version;
    std::string ip;
    // password_pending means this auth_key passed SMS-code verification but
    // the account has 2FA enabled and auth.checkPassword hasn't happened
    // yet. Business authorization must treat this state as not-logged-in,
    // permitting only completion of 2FA.
    bool password_pending = false;
    // created_at is the start of the current fully-authorized login
    // session. Bind refreshes it on every login, and completing
    // password_pending refreshes it again, so time spent waiting for 2FA
    // never satisfies payout freshness.
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point active_at;
};

// AuthKeyClientInfo is the client negotiation metadata an unauthenticated
// auth_key still needs to retain. Once logged in, device authorization is
// still expressed by Authorization. layer holds the last explicitly
// supported wire profile, letting the server seed a new session's defaults
// for the same auth key after a restart; an active session still corrects
// itself via its own explicit invokeWithLayer.
//
// Distinct from store::AuthKeyClientInfo (same name, different package in
// the Go source): this one additionally carries layer_observation_id and ip.
struct AuthKeyClientInfo {
    int layer = 0;
    // layer_observation_id is a read-only ordering token owned by the
    // protocol store. Generic client-metadata updates must never manufacture
    // or advance it; only ordered invokeWithLayer evidence may.
    std::int64_t layer_observation_id = 0;
    std::string device_model;
    std::string platform;
    std::string system_version;
    int api_id = 0;
    std::string app_version;
    // ip is the peer address (host-only) of the most recent session
    // establishment. Metadata-level merge only -- never login/bind identity
    // evidence, and never touches created_at.
    std::string ip;
};

} // namespace shuzagram::domain
