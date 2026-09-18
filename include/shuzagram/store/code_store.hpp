#pragma once

#include <cstdint>
#include <optional>
#include <string>

// A narrow slice of the store.CodeStore interface (internal/store/code.go):
// just enough for the plain phone/app-code auth.sendCode -> auth.signIn ->
// auth.signUp path. NOT ported: scoped codes (change-phone/confirm-phone),
// email login, password recovery, and the Redis-Lua atomic-with-CAS-
// revision machinery the real interface has for its production backend
// (internal/store/redisstore) -- see store::InMemoryCodeStore's own doc
// comment and NOTES/auth-sign-in-plan.md for why a single-process,
// mutex-guarded map is a legitimate first slice here rather than a
// simplification of something already working.
namespace shuzagram::store {

// PhoneCode mirrors just the fields of Go's store.PhoneCode this slice
// reads or writes.
struct PhoneCode {
    // issued_user_id is the ByPhone(phone) result AT THE TIME Set() was
    // called (0 if the phone had no owner yet) -- verification re-checks
    // this against the CURRENT owner to detect a phone-number reassignment
    // race between sendCode and signIn/signUp.
    std::int64_t issued_user_id = 0;
    bool sign_up_verified = false;
    std::string phone;
    std::string code;
    int attempts = 0;
    int max_attempts = 5;
};

enum class LoginCodeVerifyStatus { kMissing, kInvalid, kAccepted };

struct LoginCodeVerifyResult {
    LoginCodeVerifyStatus status = LoginCodeVerifyStatus::kMissing;
    PhoneCode record; // valid only when status == kAccepted
};

class ICodeStore {
public:
    virtual ~ICodeStore() = default;

    virtual void Set(const std::string& phone_code_hash, const PhoneCode& code) = 0;
    virtual std::optional<PhoneCode> Get(const std::string& phone_code_hash) = 0;
    virtual void Del(const std::string& phone_code_hash) = 0;

    // Atomically checks `code` against the record's own code. A mismatch
    // increments attempts and deletes the record once max_attempts (the
    // record's own, if set, else default_max_attempts) is reached, still
    // returning kInvalid. A match either deletes the record (ordinary
    // consumption) or, if keep_for_sign_up is true, marks it
    // sign_up_verified and keeps it (so a not-yet-registered phone's
    // subsequent auth.signUp can consume it via ConsumeSignUpVerified).
    virtual LoginCodeVerifyResult VerifyLogin(const std::string& phone_code_hash, const std::string& phone,
                                               const std::string& code, bool keep_for_sign_up,
                                               int default_max_attempts) = 0;

    // Atomically removes a record only if it exists, matches phone, and is
    // marked sign_up_verified.
    virtual std::optional<PhoneCode> ConsumeSignUpVerified(const std::string& phone_code_hash,
                                                            const std::string& phone) = 0;
};

} // namespace shuzagram::store
