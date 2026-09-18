#pragma once

#include "shuzagram/domain/user_errors.hpp"

// Errors that live in the Go source's `store` package rather than `domain`
// (internal/store/authkey.go, internal/store/authorization.go,
// internal/store/authkey_session_layer.go). Kept as a separate hierarchy
// from shuzagram::domain::Error for the same reason the Go source keeps them
// in a separate package: they describe storage/protocol-boundary invariants,
// not business rules.
namespace shuzagram::store {

class Error : public domain::Error {
public:
    explicit Error(const std::string& what) : domain::Error(what) {}
};

// A new handshake tried to write a migration-only unknown sentinel, or a
// protocol expiry outside the TL int32 timestamp range.
class InvalidAuthKeyProtocolExpiryError : public Error {
public:
    InvalidAuthKeyProtocolExpiryError() : Error("invalid auth key protocol expiry") {}
};

// The same cryptographic auth_key_id was rewritten with a different key body
// or a different permanent/temporary type/expiry.
class AuthKeyProtocolMetadataConflictError : public Error {
public:
    AuthKeyProtocolMetadataConflictError() : Error("auth key protocol metadata conflict") {}
};

// Prevents client-metadata writes from silently succeeding after the
// protocol key row has already disappeared. auth_keys is the authoritative
// Layer source; an authorization mirror must never advance on its own when
// that primary write did not happen.
class AuthKeyNotFoundError : public Error {
public:
    AuthKeyNotFoundError() : Error("auth key not found") {}
};

// Prevents an authorization from landing on a temporary/legacy-unknown key.
class AuthKeyNotPermanentError : public Error {
public:
    AuthKeyNotPermanentError() : Error("auth key is not permanent") {}
};

// A temp/perm reference is missing, has the wrong type, or its binding
// expiry isn't normalized to the handshake-authoritative value.
class AuthKeyBindingInvalidError : public Error {
public:
    AuthKeyBindingInvalidError() : Error("invalid temporary auth key binding") {}
};

class AuthorizationStateChangedError : public Error {
public:
    AuthorizationStateChangedError() : Error("authorization state changed") {}
};

class AuthKeySessionLayerInvalidError : public Error {
public:
    AuthKeySessionLayerInvalidError() : Error("invalid auth key session layer evidence") {}
};

class AuthKeySessionLayerConflictError : public Error {
public:
    AuthKeySessionLayerConflictError() : Error("conflicting auth key session layer evidence") {}
};

} // namespace shuzagram::store
