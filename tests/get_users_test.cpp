// Business-logic checks for users::ResolveGetUsers, using the same
// in-memory fake store pattern as auth_sign_in_test.cpp (not a copy of the
// real logic -- just enough storage to drive ResolveGetUsers against real
// store interfaces).

#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/users/get_users.hpp"

namespace {

using namespace shuzagram;
using mtproto::messages::InputUser;

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
    std::vector<domain::User> ByIDs(const std::vector<std::int64_t>& ids) override {
        std::vector<domain::User> out;
        for (auto id : ids) {
            if (auto it = by_id_.find(id); it != by_id_.end()) out.push_back(it->second);
        }
        return out;
    }
    std::optional<domain::User> ByPhone(const std::string&) override { Unimplemented(); }
    std::optional<domain::User> ByUsername(const std::string&) override { Unimplemented(); }
    domain::User Create(const domain::User&) override { Unimplemented(); }
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

    void Put(const domain::User& u) { by_id_[u.id] = u; }

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

void TestSelfResolvesToOwnAccountWithSelfFlag() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(1);

    domain::User me;
    me.id = 42;
    me.first_name = "Ada";
    users.Put(me);

    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 42;
    authz.Bind(a);

    InputUser self_input;
    self_input.kind = InputUser::Kind::SelfUser;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {self_input});

    Check(out.size() == 1, "inputUserSelf resolves to exactly one user");
    if (out.size() == 1) {
        Check(out[0].user.id == 42, "resolved self user has the bound user_id");
        Check(out[0].self == true, "inputUserSelf is projected with self=true");
    }
}

void TestOwnIdViaOrdinaryInputUserIsAlsoSelf() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(2);

    domain::User me;
    me.id = 7;
    me.access_hash = 555;
    users.Put(me);

    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 7;
    authz.Bind(a);

    InputUser by_id;
    by_id.kind = InputUser::Kind::ById;
    by_id.user_id = 7;
    by_id.access_hash = 555;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {by_id});

    Check(out.size() == 1, "explicit own-id inputUser resolves");
    if (out.size() == 1) {
        Check(out[0].self == true, "explicit own-id inputUser is still projected as self (matches Go's onUsersGetUsers)");
    }
}

void TestAccessHashMismatchIsDropped() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(3);

    domain::User me;
    me.id = 1;
    users.Put(me);
    domain::User other;
    other.id = 2;
    other.access_hash = 999;
    users.Put(other);

    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    authz.Bind(a);

    InputUser wrong_hash;
    wrong_hash.kind = InputUser::Kind::ById;
    wrong_hash.user_id = 2;
    wrong_hash.access_hash = 1; // wrong
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {wrong_hash});
    Check(out.empty(), "a wrong access_hash silently drops that entry, matching Go (never an error)");
}

void TestZeroAccessHashAlwaysPasses() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(4);

    domain::User me;
    me.id = 1;
    users.Put(me);
    domain::User other;
    other.id = 2;
    other.access_hash = 999;
    users.Put(other);

    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    authz.Bind(a);

    InputUser no_hash;
    no_hash.kind = InputUser::Kind::ById;
    no_hash.user_id = 2;
    no_hash.access_hash = 0; // untrusted but Go's onUsersGetUsers accepts it
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {no_hash});
    Check(out.size() == 1, "access_hash == 0 in the request always passes, matching Go's onUsersGetUsers");
}

void TestUnauthorizedAuthKeyResolvesNothing() {
    FakeUserStore users;
    FakeAuthorizationStore authz; // never bound
    const auto key = MakeAuthKeyId(5);

    domain::User me;
    me.id = 1;
    users.Put(me);

    InputUser self_input;
    self_input.kind = InputUser::Kind::SelfUser;
    InputUser by_id;
    by_id.kind = InputUser::Kind::ById;
    by_id.user_id = 1;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {self_input, by_id});
    Check(out.empty(), "an auth_key with no bound authorization resolves every input to nothing");
}

void TestPasswordPendingIsNotAuthorized() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(6);

    domain::User me;
    me.id = 1;
    users.Put(me);

    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    a.password_pending = true; // 2FA not completed yet
    authz.Bind(a);

    InputUser self_input;
    self_input.kind = InputUser::Kind::SelfUser;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {self_input});
    Check(out.empty(), "password_pending must be treated as not-logged-in, same as everywhere else in this port");
}

void TestUnknownIdIsDropped() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(7);

    domain::User me;
    me.id = 1;
    users.Put(me);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    authz.Bind(a);

    InputUser ghost;
    ghost.kind = InputUser::Kind::ById;
    ghost.user_id = 99999;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {ghost});
    Check(out.empty(), "an id with no matching user is dropped, not an error");
}

void TestInputOrderIsPreserved() {
    FakeUserStore users;
    FakeAuthorizationStore authz;
    const auto key = MakeAuthKeyId(8);

    domain::User a1;
    a1.id = 1;
    users.Put(a1);
    domain::User a2;
    a2.id = 2;
    users.Put(a2);
    domain::Authorization a;
    a.auth_key_id = key;
    a.user_id = 1;
    authz.Bind(a);

    InputUser second;
    second.kind = InputUser::Kind::ById;
    second.user_id = 2;
    InputUser self_input;
    self_input.kind = InputUser::Kind::SelfUser;
    const auto out = shuzagram::users::ResolveGetUsers(authz, users, key, {second, self_input});

    Check(out.size() == 2, "both entries resolve");
    if (out.size() == 2) {
        Check(out[0].user.id == 2, "output preserves the caller's requested order (id 2 first)");
        Check(out[1].user.id == 1 && out[1].self, "self entry comes second, matching input order");
    }
}

} // namespace

int main() {
    TestSelfResolvesToOwnAccountWithSelfFlag();
    TestOwnIdViaOrdinaryInputUserIsAlsoSelf();
    TestAccessHashMismatchIsDropped();
    TestZeroAccessHashAlwaysPasses();
    TestUnauthorizedAuthKeyResolvesNothing();
    TestPasswordPendingIsNotAuthorized();
    TestUnknownIdIsDropped();
    TestInputOrderIsPreserved();
    if (g_failures == 0) {
        std::printf("all get_users tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d get_users test(s) failed\n", g_failures);
    return 1;
}
