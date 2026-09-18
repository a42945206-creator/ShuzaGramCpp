#pragma once

#include <cstdint>
#include <stdexcept>

#include "shuzagram/domain/password.hpp"
#include "shuzagram/store/password_store.hpp"

// Port of the 2FA/SRP slice of internal/app/account/service.go
// (GetPassword/CheckPassword/defaultPasswordSettings/defaultPasswordAlgo/
// normalizePasswordSettings) backing account.getPassword and
// auth.checkPassword. See NOTES/auth-check-password-plan.md for the full
// account of what's cut: no account.updatePasswordSettings (setting a NEW
// password), no recovery email, no Passport secure-value KDF, no pending
// password reset.
//
// Kept in shuzagram::auth (not a separate shuzagram::account namespace)
// for the same pragmatic reason SignIn/SignUp/BindTempAuthKey live here:
// this project doesn't otherwise need a whole extra "account" module for
// two functions, and auth.checkPassword itself is unambiguously an auth::
// concern even though its Go backing service happens to be
// internal/app/account.
namespace shuzagram::auth {

class PasswordHashInvalidError : public std::runtime_error {
public:
    PasswordHashInvalidError() : std::runtime_error("password hash invalid") {}
};
class SrpIdInvalidError : public std::runtime_error {
public:
    SrpIdInvalidError() : std::runtime_error("srp id invalid") {}
};
class SrpPasswordChangedError : public std::runtime_error {
public:
    SrpPasswordChangedError() : std::runtime_error("srp password changed") {}
};

// The KDF algo a fresh/passwordless account reports as new_algo: bare
// 8-byte salt1 (a real password-set flow appends 32 client-random bytes to
// it -- not ported here), the fixed salt2/g/p every account on this server
// uses.
domain::PasswordAlgo DefaultPasswordAlgo();

// A passwordless account's settings: has_password=false, DefaultPasswordAlgo()
// as new_algo, and the fixed placeholder secure_random the Go source's dev
// deployments use.
domain::PasswordSettings DefaultPasswordSettings();

// account.getPassword: reads the account's settings (or synthesizes
// passwordless defaults if none exist), and -- only if a password IS set
// -- rolls and persists a fresh SRP challenge (srp_b_secret/srp_b),
// assigning srp_id once if not already assigned. Mirrors GetPassword (not
// GetPasswordWithoutRefresh) in the Go source: the ephemeral challenge is
// re-rolled on every call, never cached.
domain::PasswordSettings GetPassword(store::IPasswordStore& passwords, std::int64_t user_id);

// auth.checkPassword: verifies one SRP proof against the account's
// CURRENTLY persisted settings. Does NOT roll a new challenge -- the
// caller must have already called GetPassword to have a live srp_B to
// prove against. Throws PasswordHashInvalidError (wrong proof, or an
// inputCheckPasswordEmpty against a password-protected account, or vice
// versa), SrpIdInvalidError (stale/mismatched srp_id), or
// SrpPasswordChangedError (the password changed since the challenge this
// proof was built against).
void CheckPassword(store::IPasswordStore& passwords, std::int64_t user_id, const domain::PasswordCheck& check);

} // namespace shuzagram::auth
