#pragma once

#include <stdexcept>
#include <string>

#include "shuzagram/domain/authorization.hpp"
#include "shuzagram/store/authorization_store.hpp"
#include "shuzagram/store/code_store.hpp"
#include "shuzagram/store/user_store.hpp"

// Port of the narrow auth.sendCode -> auth.signIn -> auth.signUp slice of
// internal/app/auth/service.go (SendCode/SignIn/SignUp/verifyLoginCode/
// finishSignIn/bind). See NOTES/auth-sign-in-plan.md for the full account of
// what's cut versus the Go source:
//  - dev fixed code only (no real SMS/email provider, no auth.resendCode/
//    auth.cancelCode);
//  - no email login, no 2FA/password gating (password_pending is always
//    false -- there's no PasswordStore in this port yet);
//  - no premium grant on sign-up, no bootstrap login message;
//  - no reserved/"system user" phone check (domain::IsSystemUserID's Go
//    equivalent isn't ported).
// What IS preserved: phone normalization/validation, the exact
// owner-drift race check between issuing and verifying a code, and routing
// the actual login through the SAME store::IAuthorizationStore::Bind this
// project already verified for auth.bindTempAuthKey and the original
// pts-baseline work.
namespace shuzagram::auth {

class PhoneNumberInvalidError : public std::runtime_error {
public:
    PhoneNumberInvalidError() : std::runtime_error("phone number invalid") {}
};
class CodeExpiredError : public std::runtime_error {
public:
    CodeExpiredError() : std::runtime_error("phone code expired or not found") {}
};
class CodeInvalidError : public std::runtime_error {
public:
    CodeInvalidError() : std::runtime_error("phone code invalid") {}
};

// Issues a phone_code_hash for `phone_number` using a fixed development
// code (no real SMS/email delivery in this slice -- mirrors the Go
// source's own fallback behavior when no external provider is configured).
// Throws PhoneNumberInvalidError.
std::string SendCode(store::IUserStore& users, store::ICodeStore& codes, const std::string& phone_number,
                      const std::string& fixed_code = "12345");

struct SignInResult {
    // true: the code was correct but no account exists for this phone yet
    // -- the caller must respond with auth.authorizationSignUpRequired and
    // NOT call Bind. false: `user` is the now-authorized account.
    bool need_sign_up = false;
    domain::User user;
};

// Verifies phone_code against phone_code_hash and, if an account already
// exists for phone_number, binds `auth_template` to it via
// IAuthorizationStore::Bind (auth_template.user_id is overwritten).
// Throws CodeExpiredError, CodeInvalidError, or whatever
// IAuthorizationStore::Bind itself throws (domain::UserNotFoundError,
// domain::AccountDeletedError, store::AuthKeyNotPermanentError -- see its
// own doc comment).
SignInResult SignIn(store::IUserStore& users, store::IAuthorizationStore& authorizations, store::ICodeStore& codes,
                     const domain::Authorization& auth_template, const std::string& phone_number,
                     const std::string& phone_code_hash, const std::string& phone_code);

// Creates a new account for phone_number and binds `auth_template` to it.
// Only usable after a SignIn call on the SAME phone_code_hash returned
// need_sign_up=true (auth.signUp's own TL request carries no code -- the
// proof is the still-marked-verified code record). Throws
// domain::FirstNameInvalidError, PhoneNumberInvalidError, CodeExpiredError,
// CodeInvalidError, or whatever IUserStore::Create/IAuthorizationStore::Bind
// throw.
domain::User SignUp(store::IUserStore& users, store::IAuthorizationStore& authorizations, store::ICodeStore& codes,
                     const domain::Authorization& auth_template, const std::string& phone_number,
                     const std::string& phone_code_hash, const std::string& first_name,
                     const std::string& last_name);

} // namespace shuzagram::auth
