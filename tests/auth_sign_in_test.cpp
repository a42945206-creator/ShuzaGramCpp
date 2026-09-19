// Validation-logic checks for auth::SendCode/SignIn/SignUp, using simple
// in-memory fakes of IUserStore/IAuthorizationStore plus the REAL
// store::memory::CodeStore (it's this project's actual runtime
// implementation, not just a test double -- see its own doc comment), so
// this exercises the genuine CodeStore atomicity/attempt-counting logic,
// not a re-simplified copy of it.

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <unordered_map>

#include "shuzagram/auth/sign_in.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/net/tcp_listener.hpp"
#include "shuzagram/otpdelivery/webhook_sender.hpp"
#include "shuzagram/store/memory/code_store.hpp"

namespace {

using namespace shuzagram;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

[[noreturn]] void Unimplemented() { throw domain::NotImplementedError("fake store method not used by this test"); }

class FakeUserStore final : public store::IUserStore {
public:
    std::optional<domain::User> ByID(std::int64_t id) override {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? std::nullopt : std::optional(it->second);
    }
    std::vector<domain::User> ByIDs(const std::vector<std::int64_t>&) override { Unimplemented(); }
    std::optional<domain::User> ByPhone(const std::string& phone) override {
        if (phone.empty()) return std::nullopt;
        for (const auto& [id, u] : by_id_) {
            if (u.phone == phone) return u;
        }
        return std::nullopt;
    }
    std::optional<domain::User> ByUsername(const std::string&) override { Unimplemented(); }
    domain::User Create(const domain::User& user) override {
        domain::User u = user;
        u.id = next_id_++;
        by_id_[u.id] = u;
        return u;
    }
    domain::User SetPremiumUntil(std::int64_t, int) override { Unimplemented(); }
    domain::User SetVerified(std::int64_t, bool) override { Unimplemented(); }
    domain::User SetSupport(std::int64_t, bool) override { Unimplemented(); }
    void UpdateLastSeen(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateProfile(std::int64_t, const std::string&, const std::string&, const std::string&) override {
        Unimplemented();
    }
    domain::User UpdateUsername(std::int64_t, const std::string&) override { Unimplemented(); }
    domain::User UpdatePhone(std::int64_t, const std::string&) override { Unimplemented(); }
    domain::User SetScamFake(std::int64_t, bool, bool) override { Unimplemented(); }
    std::vector<domain::User> SweepExpiredPremium(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateEmojiStatus(std::int64_t, const domain::UserEmojiStatus&) override { Unimplemented(); }
    domain::User UpdateBirthday(std::int64_t, const domain::Birthday&) override { Unimplemented(); }
    domain::User UpdatePersonalChannel(std::int64_t, std::int64_t) override { Unimplemented(); }
    domain::User UpdateColor(std::int64_t, bool, const domain::PeerColor&) override { Unimplemented(); }

    // Test-only helper: bypasses phone-uniqueness/validation entirely, used
    // to simulate "the phone got claimed by someone else" races.
    domain::User ForceCreate(const domain::User& user) { return Create(user); }

private:
    std::unordered_map<std::int64_t, domain::User> by_id_;
    std::int64_t next_id_ = 1000;
};

class FakeAuthorizationStore final : public store::IAuthorizationStore {
public:
    void Bind(const domain::Authorization& a) override { by_key_[a.auth_key_id] = a; }
    std::optional<domain::Authorization> ByAuthKey(const std::array<std::uint8_t, 8>& id) override {
        const auto it = by_key_.find(id);
        return it == by_key_.end() ? std::nullopt : std::optional(it->second);
    }
    void UpdateClientInfo(const std::array<std::uint8_t, 8>&, const domain::AuthKeyClientInfo&) override {
        Unimplemented();
    }
    std::vector<domain::Authorization> ListByUser(std::int64_t) override { Unimplemented(); }
    void Delete(const std::array<std::uint8_t, 8>&) override { Unimplemented(); }
    std::optional<domain::Authorization> DeleteByHash(std::int64_t, std::int64_t) override { Unimplemented(); }
    std::vector<domain::Authorization> DeleteByUserExcept(std::int64_t,
                                                           const std::array<std::uint8_t, 8>&) override {
        Unimplemented();
    }
    void MarkPasswordPassed(const std::array<std::uint8_t, 8>&, std::int64_t) override { Unimplemented(); }

private:
    std::map<std::array<std::uint8_t, 8>, domain::Authorization> by_key_;
};

class FakePasswordStore final : public store::IPasswordStore {
public:
    std::optional<domain::PasswordSettings> GetByUser(std::int64_t user_id) override {
        const auto it = rows_.find(user_id);
        return it == rows_.end() ? std::nullopt : std::optional(it->second);
    }
    void Save(std::int64_t user_id, const domain::PasswordSettings& settings) override { rows_[user_id] = settings; }
    void SetHasPassword(std::int64_t user_id) {
        domain::PasswordSettings settings;
        settings.has_password = true;
        rows_[user_id] = settings;
    }

private:
    std::map<std::int64_t, domain::PasswordSettings> rows_;
};

std::array<std::uint8_t, 8> MakeAuthKeyId(std::uint64_t seed) {
    std::array<std::uint8_t, 8> id{};
    std::memcpy(id.data(), &seed, 8);
    return id;
}

struct Fixture {
    FakeUserStore users;
    FakeAuthorizationStore authorizations;
    store::memory::CodeStore codes;
    domain::Authorization auth_template;

    explicit Fixture(std::uint64_t auth_key_seed) { auth_template.auth_key_id = MakeAuthKeyId(auth_key_seed); }
};

void TestSignInExistingUser() {
    Fixture f(1);
    domain::User existing;
    existing.phone = "15550001111";
    existing.first_name = "Ada";
    const auto created = f.users.ForceCreate(existing);

    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 1111");
    const auto result = auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 1111", hash,
                                      "12345");
    Check(!result.need_sign_up, "SignIn on an existing user's correct code does not need sign-up");
    Check(result.user.id == created.id, "SignIn returns the existing user");

    const auto bound = f.authorizations.ByAuthKey(f.auth_template.auth_key_id);
    Check(bound.has_value() && bound->user_id == created.id, "SignIn binds the authorization to the existing user");
}

void TestSignInThenSignUpForNewUser() {
    Fixture f(2);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 2222");

    const auto first = auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 2222", hash,
                                     "12345");
    Check(first.need_sign_up, "SignIn on a never-registered phone's correct code needs sign-up");
    Check(!f.authorizations.ByAuthKey(f.auth_template.auth_key_id).has_value(),
          "need_sign_up path does not bind any authorization yet");

    // A client re-calling auth.signIn before auth.signUp (real clients do
    // this) must still see need_sign_up without consuming the marker.
    const auto second = auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 2222", hash,
                                      "12345");
    Check(second.need_sign_up, "a second SignIn call on the same hash still reports need_sign_up");

    const auto created = auth::SignUp(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 2222", hash,
                                       "Grace", "Hopper");
    Check(created.first_name == "Grace" && created.last_name == "Hopper" && created.phone == "15550002222",
          "SignUp creates the user with the given name and normalized phone");
    const auto bound = f.authorizations.ByAuthKey(f.auth_template.auth_key_id);
    Check(bound.has_value() && bound->user_id == created.id, "SignUp binds the authorization to the new user");
}

void TestSignInWrongCodeThenExhaustsAttempts() {
    Fixture f(3);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 3333");

    int invalid_count = 0;
    for (int i = 0; i < 5; ++i) {
        try {
            auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 3333", hash, "00000");
            Check(false, "wrong code should never succeed");
        } catch (const auth::CodeInvalidError&) {
            ++invalid_count;
        } catch (const auth::CodeExpiredError&) {
            break; // attempts exhausted -- the record is gone now
        }
    }
    Check(invalid_count == 5, "5 wrong attempts (the default max) all report PHONE_CODE_INVALID");

    try {
        auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 3333", hash, "12345");
        Check(false, "the code should have been erased after exhausting attempts");
    } catch (const auth::CodeExpiredError&) {
        Check(true, "the correct code no longer works once attempts are exhausted");
    }
}

void TestSignInUnknownHash() {
    Fixture f(4);
    try {
        auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 4444", "nosuchhash", "12345");
        Check(false, "an unknown phone_code_hash should throw");
    } catch (const auth::CodeExpiredError&) {
        Check(true, "an unknown phone_code_hash throws CodeExpiredError");
    }
}

void TestSignInOwnerDriftIsRejected() {
    Fixture f(5);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 5555");
    // Someone else registers this exact phone AFTER the code was issued
    // but BEFORE it's verified.
    domain::User drifted;
    drifted.phone = "15550005555";
    f.users.ForceCreate(drifted);

    try {
        auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 5555", hash, "12345");
        Check(false, "a phone-owner drift between sendCode and signIn should throw");
    } catch (const auth::CodeInvalidError&) {
        Check(true, "phone-owner drift throws CodeInvalidError rather than authorizing the wrong account");
    }
}

void TestSignUpRejectsEmptyFirstName() {
    Fixture f(6);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 6666");
    auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 6666", hash, "12345");
    try {
        auth::SignUp(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 6666", hash, "", "Nobody");
        Check(false, "an empty first name should throw");
    } catch (const domain::FirstNameInvalidError&) {
        Check(true, "SignUp rejects an empty first name with FirstNameInvalidError");
    }
}

void TestSignUpWithoutPriorSignInIsRejected() {
    Fixture f(7);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 7777");
    // No SignIn call happened on this hash -- it was never marked
    // sign_up_verified.
    try {
        auth::SignUp(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 7777", hash, "Nobody", "");
        Check(false, "SignUp without a prior verified SignIn should throw");
    } catch (const auth::CodeInvalidError&) {
        Check(true, "SignUp without a prior verified SignIn throws CodeInvalidError");
    }
}

void TestSignInWithPasswordThrowsSessionPasswordNeeded() {
    Fixture f(8);
    domain::User existing;
    existing.phone = "15550008888";
    const auto created = f.users.ForceCreate(existing);
    FakePasswordStore passwords;
    passwords.SetHasPassword(created.id);

    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 8888");
    try {
        auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 8888", hash, "12345",
                     &passwords);
        Check(false, "SignIn on a 2FA-protected account should throw SessionPasswordNeededError");
    } catch (const auth::SessionPasswordNeededError&) {
        Check(true, "SignIn throws SessionPasswordNeededError for a password-protected account");
    }
    const auto bound = f.authorizations.ByAuthKey(f.auth_template.auth_key_id);
    Check(bound.has_value() && bound->user_id == created.id && bound->password_pending,
          "SignIn still binds the authorization, with password_pending=true, before throwing");
}

// Helper server for the OTP-webhook SendCode tests below: reads one raw
// HTTP request off a real loopback socket, extracts the JSON body's "code"
// field with a plain substring search (good enough for a fixed-shape test
// fixture), and answers with the given canned response.
std::string ReadRequestBody(net::TcpSocket& socket) {
    std::string head;
    std::uint8_t byte = 0;
    while (head.size() < 4 || head.compare(head.size() - 4, 4, "\r\n\r\n") != 0) {
        socket.ReadExact(&byte, 1);
        head.push_back(static_cast<char>(byte));
    }
    std::size_t content_length = 0;
    const auto cl_pos = head.find("Content-Length:");
    if (cl_pos != std::string::npos) content_length = static_cast<std::size_t>(std::stoul(head.substr(cl_pos + 16)));
    std::string body(content_length, '\0');
    if (content_length > 0) socket.ReadExact(reinterpret_cast<std::uint8_t*>(body.data()), content_length);
    return body;
}

std::string ExtractJsonStringField(const std::string& body, const std::string& key) {
    const auto needle = "\"" + key + "\":\"";
    const auto pos = body.find(needle);
    if (pos == std::string::npos) return "";
    const auto start = pos + needle.size();
    const auto end = body.find('"', start);
    return body.substr(start, end - start);
}

void TestSendCodeWithOtpSenderGeneratesRandomCodeAndDelivers() {
    net::TcpListener listener("127.0.0.1", 0);
    std::string delivered_code;
    std::string delivered_recipient;

    std::thread server([&] {
        auto socket = listener.Accept();
        const auto body = ReadRequestBody(socket);
        delivered_code = ExtractJsonStringField(body, "code");
        delivered_recipient = ExtractJsonStringField(body, "recipient");
        const std::string resp_body = R"({"accepted":true,"message_id":"m1"})";
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(resp_body.size()) + "\r\n\r\n" + resp_body;
        socket.WriteAll(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
    });

    otpdelivery::WebhookSender::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(listener.Port()) + "/otp";
    config.timeout = std::chrono::seconds(5);
    otpdelivery::WebhookSender sender(config);

    Fixture f(20);
    const auto hash = auth::SendCode(f.users, f.codes, "+1 555 000 2000", "12345", &sender, /*code_length=*/5);
    server.join();

    Check(delivered_recipient == "15550002000", "the normalized phone is sent as the recipient");
    Check(delivered_code.size() == 5, "a real 5-digit code is generated when an OTP sender is configured");
    Check(delivered_code != "12345", "the delivered code is not the fixed dev code");
    for (char c : delivered_code) Check(c >= '0' && c <= '9', "every character of the code is a digit");

    // The code the client must submit is exactly the one that was
    // delivered, not the fixed dev code -- SignIn must accept it.
    const auto result = auth::SignIn(f.users, f.authorizations, f.codes, f.auth_template, "+1 555 000 2000", hash,
                                      delivered_code);
    Check(result.need_sign_up, "no account exists yet for this phone, so sign-up is required");
}

void TestSendCodeRollsBackOnDeliveryFailure() {
    net::TcpListener listener("127.0.0.1", 0);
    const auto port = listener.Port();
    listener.Close(); // nothing is listening -- every delivery attempt fails

    otpdelivery::WebhookSender::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(port) + "/otp";
    config.timeout = std::chrono::seconds(1);
    otpdelivery::WebhookSender sender(config);

    Fixture f(21);
    bool threw = false;
    try {
        auth::SendCode(f.users, f.codes, "+1 555 000 2001", "12345", &sender);
    } catch (const otpdelivery::DeliveryFailedError&) {
        threw = true;
    }
    Check(threw, "SendCode propagates a delivery failure instead of silently succeeding");
    // SendCode never returns the hash on this path (the exception propagates
    // before its `return hash` line), so there is no key a black-box test
    // could look up to confirm codes.Del(hash) ran -- that rollback call is
    // covered by reading sign_in.cpp directly (mirrors rollbackUndeliveredCode
    // in the Go source) rather than by a second, store-internals-peeking test.
}

} // namespace

int main() {
    TestSignInExistingUser();
    TestSignInThenSignUpForNewUser();
    TestSignInWrongCodeThenExhaustsAttempts();
    TestSignInUnknownHash();
    TestSignInOwnerDriftIsRejected();
    TestSignUpRejectsEmptyFirstName();
    TestSignUpWithoutPriorSignInIsRejected();
    TestSignInWithPasswordThrowsSessionPasswordNeeded();
    TestSendCodeWithOtpSenderGeneratesRandomCodeAndDelivers();
    TestSendCodeRollsBackOnDeliveryFailure();
    if (g_failures == 0) {
        std::printf("all auth::SendCode/SignIn/SignUp tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d auth::SendCode/SignIn/SignUp test(s) failed\n", g_failures);
    return 1;
}
