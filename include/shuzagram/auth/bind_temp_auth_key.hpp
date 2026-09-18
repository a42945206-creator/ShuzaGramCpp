#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "shuzagram/store/auth_key_store.hpp"
#include "shuzagram/store/temp_auth_key_store.hpp"

// Port of internal/app/auth/service.go's BindTempAuthKey +
// validateBindTempAuthKey (the narrow slice this project actually needs --
// see NOTES/bind-temp-auth-key-plan.md for what's deliberately left out:
// per-session Layer-cache invalidation and session/login-token push side
// effects that don't exist in this project, since it has no
// Sessions/Router equivalent to invalidate or push through).
//
// Deliberately its own small library (shuzagram_auth) rather than living in
// shuzagram_mtproto or shuzagram_store_postgres: it's the one piece of
// logic that needs BOTH crypto (to decrypt/verify the proof) and store
// (to load/persist auth keys), mirroring how the Go source's
// internal/app/auth package imports both internal/store and
// github.com/iamxvbaba/td/crypto while neither of ITS dependencies imports
// it back.
namespace shuzagram::auth {

// Public error sentinels, one-to-one with auth service.go's Err* (there
// mapped to MTProto RPC error strings by internal/rpc/errors.go's
// bindTempAuthKeyErr -- this project's own RPC handler does the equivalent
// mapping, kept out of this function so it stays independent of any
// MTProto-error-envelope concern).
class ExpiresAtInvalidError : public std::runtime_error {
public:
    ExpiresAtInvalidError() : std::runtime_error("temporary auth key request expiry invalid") {}
};
class TempAuthKeyEmptyError : public std::runtime_error {
public:
    TempAuthKeyEmptyError() : std::runtime_error("temporary auth key missing or expired") {}
};
class EncryptedMessageInvalidError : public std::runtime_error {
public:
    EncryptedMessageInvalidError() : std::runtime_error("encrypted message invalid") {}
};

struct BindTempAuthKeyRequest {
    std::array<std::uint8_t, 8> temp_auth_key_id{}; // this connection's own auth_key_id
    std::int64_t temp_session_id = 0;                // this connection's own session_id
    std::int64_t perm_auth_key_id = 0;
    std::int64_t nonce = 0;
    int expires_at = 0;
    std::vector<std::uint8_t> encrypted_message;
};

// Validates and commits one auth.bindTempAuthKey call:
//  1. loads+touches both the temp and permanent auth_keys rows in one
//     statement (auth_keys.LoadBindingKeys);
//  2. confirms the temp key is genuinely temporary and not yet expired, and
//     the permanent key is genuinely permanent;
//  3. decrypts encrypted_message under the PERMANENT key's body (proving
//     the caller possesses it) and cross-checks every field of the
//     decrypted bind_auth_key_inner against the request/session;
//  4. persists the binding via temp_keys, which independently re-validates
//     against the database and atomically merges Layer defaults -- this
//     function does not duplicate that merge as a pre-check the way the Go
//     source's validateBindTempAuthKey does (a documented, harmless scope
//     cut: the database's own answer is authoritative either way).
//
// Throws ExpiresAtInvalidError, TempAuthKeyEmptyError,
// EncryptedMessageInvalidError, or whatever temp_keys.SaveWithState itself
// throws (store::TempAuthKeyAlreadyBoundError,
// store::AuthKeySessionLayerInvalidError/ConflictError, ...).
domain::TempAuthKeyBindingResult BindTempAuthKey(store::IAuthKeyStore& auth_keys,
                                                  store::ITempAuthKeyBindingStore& temp_keys,
                                                  const BindTempAuthKeyRequest& req);

} // namespace shuzagram::auth
