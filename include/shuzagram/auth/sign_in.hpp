#pragma once

#include <chrono>
#include <stdexcept>
#include <string>

#include "shuzagram/domain/authorization.hpp"
#include "shuzagram/otpdelivery/webhook_sender.hpp"
#include "shuzagram/store/authorization_store.hpp"
#include "shuzagram/store/code_store.hpp"
#include "shuzagram/store/password_store.hpp"
#include "shuzagram/store/user_store.hpp"

// Port of the narrow auth.sendCode -> auth.signIn -> auth.signUp slice of
// internal/app/auth/service.go (SendCode/SignIn/SignUp/verifyLoginCode/
// finishSignIn/bind). See NOTES/auth-sign-in-plan.md for the full account of
// what's cut versus the Go source:
//  - dev fixed code only (no real SMS/email provider, no auth.resendCode/
//    auth.cancelCode);
//  - no email login;
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
// Thrown by SignIn AFTER it has already bound auth_template to the
// account (with password_pending=true) -- matches the Go source's
// finishSignIn: a 2FA-protected account's auth_key is deliberately bound
// early (so it has a durable identity to complete auth.checkPassword
// against) but the RPC layer must still tell the client the login is not
// yet complete. Callers must map this to SESSION_PASSWORD_NEEDED, not
// treat it as an ordinary failure that leaves nothing bound.
class SessionPasswordNeededError : public std::runtime_error {
public:
    SessionPasswordNeededError() : std::runtime_error("session password needed") {}
};

// Issues a phone_code_hash for `phone_number`. With otp_sender == nullptr,
// uses a fixed development code and delivers nothing -- mirrors the Go
// source's own fallback behavior when no external provider is configured
// (createPhoneCode's `code := s.fixedCode` branch, not a simplification
// unique to this port). With a real otp_sender, mirrors the Go source's
// provider branch exactly: a fresh random code_length-digit code is
// generated and delivered through the "OTP Webhook v1" protocol (see
// NOTES/otp-webhook-delivery-plan.md); a delivery failure rolls the issued
// code back and rethrows otpdelivery::DeliveryFailedError, so a caller
// never ends up with a code that was never actually sent anywhere.
//
// Throws PhoneNumberInvalidError, or otpdelivery::DeliveryFailedError if
// otp_sender is set and delivery fails.
std::string SendCode(store::IUserStore& users, store::ICodeStore& codes, const std::string& phone_number,
                      const std::string& fixed_code = "12345", otpdelivery::WebhookSender* otp_sender = nullptr,
                      int code_length = 5, std::chrono::seconds code_ttl = std::chrono::seconds(300));

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
//
// passwords, if non-null, gates 2FA exactly like the Go source's
// finishSignIn: when the account has a password set, auth_template is
// bound with password_pending=true and then SessionPasswordNeededError is
// thrown (Bind has already happened -- see that error's own doc comment).
// Passing nullptr (the default) skips this check entirely, matching a nil
// PasswordStore in the Go source (password_pending is always false).
//
// Throws CodeExpiredError, CodeInvalidError, SessionPasswordNeededError,
// or whatever IAuthorizationStore::Bind itself throws
// (domain::UserNotFoundError, domain::AccountDeletedError,
// store::AuthKeyNotPermanentError -- see its own doc comment).
SignInResult SignIn(store::IUserStore& users, store::IAuthorizationStore& authorizations, store::ICodeStore& codes,
                     const domain::Authorization& auth_template, const std::string& phone_number,
                     const std::string& phone_code_hash, const std::string& phone_code,
                     store::IPasswordStore* passwords = nullptr);

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
