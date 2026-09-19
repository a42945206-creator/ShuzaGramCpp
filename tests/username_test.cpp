// Business-logic checks for users::NormalizeUsername/ValidUsername/
// CheckUsername/UpdateUsername, ported from
// internal/app/users/service.go's normalizeUsername/validUsername/
// CheckUsername/UpdateUsername, using the same fake-store pattern as the
// other tests in this directory.

#include <cstdio>
#include <string>
#include <unordered_map>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/users/username.hpp"

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
    std::optional<domain::User> ByUsername(const std::string& username) override {
        for (const auto& [id, u] : by_id_) {
            (void)id;
            if (u.username == username) return u;
        }
        return std::nullopt;
    }
    domain::User Create(const domain::User&) override { Unimplemented(); }
    domain::User SetPremiumUntil(std::int64_t, int) override { Unimplemented(); }
    domain::User SetVerified(std::int64_t, bool) override { Unimplemented(); }
    domain::User SetSupport(std::int64_t, bool) override { Unimplemented(); }
    void UpdateLastSeen(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateProfile(std::int64_t, const std::string&, const std::string&, const std::string&) override {
        Unimplemented();
    }
    domain::User UpdateUsername(std::int64_t user_id, const std::string& username) override {
        ++update_calls;
        auto& u = by_id_.at(user_id);
        u.username = username;
        return u;
    }
    domain::User UpdatePhone(std::int64_t, const std::string&) override { Unimplemented(); }
    domain::User SetScamFake(std::int64_t, bool, bool) override { Unimplemented(); }
    std::vector<domain::User> SweepExpiredPremium(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateEmojiStatus(std::int64_t, const domain::UserEmojiStatus&) override { Unimplemented(); }
    domain::User UpdateBirthday(std::int64_t, const domain::Birthday&) override { Unimplemented(); }
    domain::User UpdatePersonalChannel(std::int64_t, std::int64_t) override { Unimplemented(); }
    domain::User UpdateColor(std::int64_t, bool, const domain::PeerColor&) override { Unimplemented(); }

    void Put(const domain::User& u) { by_id_[u.id] = u; }

    int update_calls = 0;

private:
    std::unordered_map<std::int64_t, domain::User> by_id_;
};

void TestNormalizeUsernameStripsAtAndSpace() {
    Check(users::NormalizeUsername("  @alice  ") == "alice", "leading/trailing space and '@' are stripped");
    Check(users::NormalizeUsername("alice") == "alice", "an already-clean username is unchanged");
    Check(users::NormalizeUsername("   ") == "", "all-whitespace normalizes to empty");
}

void TestValidUsernameRules() {
    Check(users::ValidUsername("alice"), "a plain 5-letter username is valid");
    Check(!users::ValidUsername("bob"), "shorter than 5 chars is invalid");
    Check(!users::ValidUsername(std::string(33, 'a')), "longer than 32 chars is invalid");
    Check(!users::ValidUsername("1alice"), "must not start with a digit");
    Check(!users::ValidUsername("_alice"), "must not start with an underscore");
    Check(users::ValidUsername("alice_1"), "digits/underscore allowed after the first character");
    Check(!users::ValidUsername("alice!"), "punctuation outside '_' is invalid");
}

void TestCheckUsernameAvailableForNewName() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    Check(users::CheckUsername(store, 1, "newname") == true, "an unclaimed valid username is available");
}

void TestCheckUsernameOwnCurrentNameIsAvailable() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    me.username = "alice";
    store.Put(me);
    Check(users::CheckUsername(store, 1, "alice") == true, "the caller's own current username reports available");
}

void TestCheckUsernameTakenBySomeoneElseIsUnavailable() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    domain::User other;
    other.id = 2;
    other.username = "alice";
    store.Put(other);
    Check(users::CheckUsername(store, 1, "alice") == false, "a username held by another user is unavailable");
}

void TestCheckUsernameEmptyIsInvalid() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    bool threw = false;
    try {
        users::CheckUsername(store, 1, "");
    } catch (const domain::UsernameInvalidError&) {
        threw = true;
    }
    Check(threw, "unlike UpdateUsername, CheckUsername treats \"\" as invalid, not as a valid answer");
}

void TestCheckUsernameUnauthorizedThrowsUserNotFound() {
    FakeUserStore store;
    bool threw = false;
    try {
        users::CheckUsername(store, 0, "alice");
    } catch (const domain::UserNotFoundError&) {
        threw = true;
    }
    Check(threw, "user_id == 0 (unauthorized) throws UserNotFoundError, never silently succeeds");
}

void TestUpdateUsernameSetsNewName() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    const auto result = users::UpdateUsername(store, 1, "  @alice  ");
    Check(result.username == "alice", "the new username is normalized before being stored");
    Check(store.update_calls == 1, "store is written exactly once");
}

void TestUpdateUsernameEmptyClearsWithoutValidation() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    me.username = "alice";
    store.Put(me);
    const auto result = users::UpdateUsername(store, 1, "");
    Check(result.username.empty(), "an empty username clears the current one");
    Check(store.update_calls == 1, "clearing still writes to the store");
}

void TestUpdateUsernameNoopSkipsStoreWrite() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    me.username = "alice";
    store.Put(me);
    const auto result = users::UpdateUsername(store, 1, "alice");
    Check(result.username == "alice", "result reflects the unchanged username");
    Check(store.update_calls == 0, "no store write happens when the username doesn't actually change");
}

void TestUpdateUsernameInvalidThrows() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    bool threw = false;
    try {
        users::UpdateUsername(store, 1, "ab");
    } catch (const domain::UsernameInvalidError&) {
        threw = true;
    }
    Check(threw, "a too-short username throws UsernameInvalidError");
    Check(store.update_calls == 0, "no store write happens on validation failure");
}

void TestUpdateUsernameOccupiedThrows() {
    FakeUserStore store;
    domain::User me;
    me.id = 1;
    store.Put(me);
    domain::User other;
    other.id = 2;
    other.username = "alice";
    store.Put(other);
    bool threw = false;
    try {
        users::UpdateUsername(store, 1, "alice");
    } catch (const domain::UsernameOccupiedError&) {
        threw = true;
    }
    Check(threw, "a username held by someone else throws UsernameOccupiedError");
    Check(store.update_calls == 0, "no store write happens when the username is occupied");
}

} // namespace

int main() {
    TestNormalizeUsernameStripsAtAndSpace();
    TestValidUsernameRules();
    TestCheckUsernameAvailableForNewName();
    TestCheckUsernameOwnCurrentNameIsAvailable();
    TestCheckUsernameTakenBySomeoneElseIsUnavailable();
    TestCheckUsernameEmptyIsInvalid();
    TestCheckUsernameUnauthorizedThrowsUserNotFound();
    TestUpdateUsernameSetsNewName();
    TestUpdateUsernameEmptyClearsWithoutValidation();
    TestUpdateUsernameNoopSkipsStoreWrite();
    TestUpdateUsernameInvalidThrows();
    TestUpdateUsernameOccupiedThrows();
    if (g_failures == 0) {
        std::printf("all username tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d username test(s) failed\n", g_failures);
    return 1;
}
