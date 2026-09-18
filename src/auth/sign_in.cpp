#include "shuzagram/auth/sign_in.hpp"

#include <cstring>

#include "shuzagram/domain/phone.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"

// Ported from internal/app/auth/service.go's SendCode/SignIn/SignUp/
// verifyLoginCode/finishSignIn/bind -- see the header for exact scope.
namespace shuzagram::auth {

namespace {

std::string RandomHex(std::size_t n) {
    const auto bytes = mtproto::crypto::SystemRandomBytes(n);
    static const char kHex[] = "0123456789abcdef";
    std::string out(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i] = kHex[bytes[i] >> 4];
        out[2 * i + 1] = kHex[bytes[i] & 0xF];
    }
    return out;
}

std::int64_t RandomInt64() {
    const auto bytes = mtproto::crypto::SystemRandomBytes(8);
    std::int64_t v;
    std::memcpy(&v, bytes.data(), 8);
    return v;
}

// currentPhoneOwner in the Go source: 0 if unowned.
std::int64_t CurrentPhoneOwnerId(store::IUserStore& users, const std::string& phone) {
    const auto owner = users.ByPhone(phone);
    return owner ? owner->id : 0;
}

// Shared by SignIn (proof = a fresh code) and the sign-up-required
// continuation (proof = the still-marked-verified record from an earlier
// SignIn call on the same hash). Returns found=false when the code was
// correct but no account exists yet.
struct VerifiedLogin {
    bool found = false;
    domain::User user;
};

VerifiedLogin VerifyLoginCode(store::IUserStore& users, store::ICodeStore& codes, const std::string& phone,
                               const std::string& phone_code_hash, const std::string& phone_code) {
    constexpr int kDefaultMaxAttempts = 5;

    const auto rec = codes.Get(phone_code_hash);
    if (!rec) throw CodeExpiredError();
    if (rec->phone != phone) throw CodeInvalidError();

    const std::int64_t before_owner = CurrentPhoneOwnerId(users, phone);
    if (rec->issued_user_id != before_owner) {
        // The phone changed hands between sendCode and now -- this hash
        // can never legitimately authorize whoever holds it today.
        codes.Del(phone_code_hash);
        throw CodeInvalidError();
    }

    if (rec->sign_up_verified) {
        // A previous SignIn call on this exact hash already verified the
        // code and is waiting for SignUp. Re-checking here (rather than
        // re-running VerifyLogin, which would consume a record SignUp
        // still needs) lets a client call auth.signIn a second time
        // without losing the pending sign-up. Simplified vs. the Go
        // source: plain equality instead of a constant-time compare.
        if (before_owner != 0 || rec->code != phone_code) throw CodeInvalidError();
        return {false, {}};
    }

    const bool keep_for_sign_up = before_owner == 0;
    const auto result = codes.VerifyLogin(phone_code_hash, phone, phone_code, keep_for_sign_up, kDefaultMaxAttempts);

    const std::int64_t after_owner = CurrentPhoneOwnerId(users, phone);
    if (before_owner != after_owner) {
        codes.Del(phone_code_hash);
        throw CodeInvalidError();
    }

    switch (result.status) {
        case store::LoginCodeVerifyStatus::kMissing:
            throw CodeExpiredError();
        case store::LoginCodeVerifyStatus::kInvalid:
            throw CodeInvalidError();
        case store::LoginCodeVerifyStatus::kAccepted:
            if (after_owner == 0) return {false, {}};
            // ByPhone is re-read (not just "found") so the returned user is
            // the current row, not a stale copy from before verification.
            if (const auto u = users.ByPhone(phone)) return {true, *u};
            return {false, {}};
    }
    throw domain::Error("unreachable: unknown LoginCodeVerifyStatus");
}

} // namespace

std::string SendCode(store::IUserStore& users, store::ICodeStore& codes, const std::string& phone_number,
                      const std::string& fixed_code) {
    const std::string phone = domain::NormalizePhone(phone_number);
    if (!domain::ValidPhone(phone)) throw PhoneNumberInvalidError();

    const std::string hash = RandomHex(8);
    store::PhoneCode rec;
    rec.issued_user_id = CurrentPhoneOwnerId(users, phone);
    rec.phone = phone;
    rec.code = fixed_code;
    codes.Set(hash, rec);
    return hash;
}

SignInResult SignIn(store::IUserStore& users, store::IAuthorizationStore& authorizations, store::ICodeStore& codes,
                     const domain::Authorization& auth_template, const std::string& phone_number,
                     const std::string& phone_code_hash, const std::string& phone_code) {
    const std::string phone = domain::NormalizePhone(phone_number);
    const VerifiedLogin verified = VerifyLoginCode(users, codes, phone, phone_code_hash, phone_code);
    if (!verified.found) return {true, {}};

    domain::Authorization a = auth_template;
    a.user_id = verified.user.id;
    authorizations.Bind(a);
    return {false, verified.user};
}

domain::User SignUp(store::IUserStore& users, store::IAuthorizationStore& authorizations, store::ICodeStore& codes,
                     const domain::Authorization& auth_template, const std::string& phone_number,
                     const std::string& phone_code_hash, const std::string& first_name,
                     const std::string& last_name) {
    const std::string phone = domain::NormalizePhone(phone_number);
    if (!domain::ValidPhone(phone)) throw PhoneNumberInvalidError();
    if (first_name.empty()) throw domain::FirstNameInvalidError();

    const auto rec = codes.Get(phone_code_hash);
    if (!rec) throw CodeExpiredError();
    if (rec->phone != phone || !rec->sign_up_verified || rec->issued_user_id != 0) {
        throw CodeInvalidError();
    }
    if (CurrentPhoneOwnerId(users, phone) != 0) {
        // Someone already claimed this phone since the verifying SignIn
        // call -- the marker is now stale.
        codes.Del(phone_code_hash);
        throw CodeInvalidError();
    }

    const auto consumed = codes.ConsumeSignUpVerified(phone_code_hash, phone);
    if (!consumed) throw CodeExpiredError();
    if (consumed->issued_user_id != 0 || !consumed->sign_up_verified) throw CodeInvalidError();
    if (CurrentPhoneOwnerId(users, phone) != 0) throw CodeInvalidError();

    domain::User draft;
    draft.phone = phone;
    draft.first_name = first_name;
    draft.last_name = last_name;
    draft.access_hash = RandomInt64();
    const domain::User created = users.Create(draft);

    domain::Authorization a = auth_template;
    a.user_id = created.id;
    authorizations.Bind(a);
    return created;
}

} // namespace shuzagram::auth
