// Business-logic checks for account::UpdateStatus / auth::ResolveCurrentUser,
// using the same in-memory fake store pattern as auth_sign_in_test.cpp and
// get_users_test.cpp.

#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

#include "shuzagram/account/update_status.hpp"
#include "shuzagram/auth/current_user.hpp"
#include "shuzagram/domain/user_errors.hpp"

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
    std::optional<domain::User> ByPhone(const std::string&) override { Unimplemented(); }
    std::optional<domain::User> ByUsername(const std::string&) override { Unimplemented(); }
    domain::User Create(const domain::User&) override { Unimplemented(); }
    domain::User SetPremiumUntil(std::int64_t, int) override { Unimplemented(); }
    domain::User SetVerified(std::int64_t, bool) override { Unimplemented(); }
    domain::User SetSupport(std::int64_t, bool) override { Unimplemented(); }
    void UpdateLastSeen(std::int64_t user_id, int last_seen_at) override {
        ++update_calls;
        last_updated_user_id = user_id;
        last_updated_at = last_seen_at;
    }
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

    void Put(const domain::User& u) { by_id_[u.id] = u; }

    int update_calls = 0;
    std::int64_t last_updated_user_id = 0;
    int last_updated_at = 0;

private:
    std::unordered_map<std::int64_t, domain::User> by_id_;
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

std::array<std::uint8_t, 8> MakeAuthKeyId(std::uint64_t seed) {
    std::array<std::uint8_t, 8> id{};
    std::memcpy(id.data(), &seed, 8);
    return id;
}

void TestResolveCurrentUserUnboundAuthKey() {
    FakeAuthorizationStore authz;
    const auto current = auth::ResolveCurrentUser(authz, MakeAuthKeyId(1));
    Check(!current.authorized, "an unbound auth_key is never authorized");
    Check(current.user_id == 0, "user_id is 0 when unauthorized");
}

void TestResolveCurrentUserBoundAuthKey() {
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(2);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 77;
    authz.Bind(a);

    const auto current = auth::ResolveCurrentUser(authz, key);
    Check(current.authorized, "a bound, non-pending auth_key is authorized");
    Check(current.user_id == 77, "resolves to the bound user_id");
}

void TestResolveCurrentUserPasswordPending() {
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(3);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 5;
    a.password_pending = true;
    authz.Bind(a);

    const auto current = auth::ResolveCurrentUser(authz, key);
    Check(!current.authorized, "password_pending must be treated as not-logged-in");
}

void TestUpdateStatusPersistsLastSeenForAuthorizedCaller() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(4);
    domain::User me;
    me.id = 9;
    users.Put(me);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 9;
    authz.Bind(a);

    account::UpdateStatus(authz, users, key, 123456);
    Check(users.update_calls == 1, "UpdateLastSeen is called exactly once");
    Check(users.last_updated_user_id == 9, "UpdateLastSeen targets the bound user_id");
    Check(users.last_updated_at == 123456, "UpdateLastSeen is given the caller's now");
}

void TestUpdateStatusIsNoOpForUnauthorizedCaller() {
    FakeUserStore users;
    FakeAuthorizationStore authz; // never bound
    const auto key = MakeAuthKeyId(5);

    account::UpdateStatus(authz, users, key, 123456);
    Check(users.update_calls == 0, "an unauthorized auth_key never touches the store, matching onAccountUpdateStatus");
}

void TestUpdateStatusIsNoOpWhilePasswordPending() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(6);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    a.password_pending = true;
    authz.Bind(a);

    account::UpdateStatus(authz, users, key, 123456);
    Check(users.update_calls == 0, "password_pending is a no-op, same as everywhere else in this port");
}

} // namespace

int main() {
    TestResolveCurrentUserUnboundAuthKey();
    TestResolveCurrentUserBoundAuthKey();
    TestResolveCurrentUserPasswordPending();
    TestUpdateStatusPersistsLastSeenForAuthorizedCaller();
    TestUpdateStatusIsNoOpForUnauthorizedCaller();
    TestUpdateStatusIsNoOpWhilePasswordPending();
    if (g_failures == 0) {
        std::printf("all update_status tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d update_status test(s) failed\n", g_failures);
    return 1;
}
