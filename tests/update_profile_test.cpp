// Business-logic checks for users::UpdateProfile (the account.updateProfile
// partial-update merge/validation, ported from
// internal/app/users/service.go's Service.UpdateProfile), using the same
// fake-store pattern as get_users_test.cpp/update_status_test.cpp.

#include <cstdio>
#include <string>
#include <unordered_map>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/users/update_profile.hpp"

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
    void UpdateLastSeen(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateProfile(std::int64_t user_id, const std::string& first_name, const std::string& last_name,
                                const std::string& about) override {
        ++update_calls;
        auto& u = by_id_.at(user_id);
        u.first_name = first_name;
        u.last_name = last_name;
        u.about = about;
        return u;
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

private:
    std::unordered_map<std::int64_t, domain::User> by_id_;
};

void TestPartialUpdateOnlyChangesFlaggedFields() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    u.last_name = "Lovelace";
    u.about = "old about";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_about = true;
    update.about = "new about";

    const auto result = users::UpdateProfile(store, 1, update, 1000);
    Check(result.first_name == "Ada", "first_name is preserved when not flagged");
    Check(result.last_name == "Lovelace", "last_name is preserved when not flagged");
    Check(result.about == "new about", "about is updated when flagged");
    Check(store.update_calls == 1, "store is written exactly once");
}

void TestTrimsWhitespace() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_last_name = true;
    update.last_name = "  Lovelace  ";

    const auto result = users::UpdateProfile(store, 1, update, 1000);
    Check(result.last_name == "Lovelace", "surrounding whitespace is trimmed");
}

void TestUnchangedUpdateSkipsStoreWrite() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    u.last_name = "Lovelace";
    u.about = "same";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_about = true;
    update.about = "same"; // identical to current value

    const auto result = users::UpdateProfile(store, 1, update, 1000);
    Check(result.about == "same", "unchanged result is still returned correctly");
    Check(store.update_calls == 0, "no store write happens when nothing actually changed");
}

void TestEmptyFirstNameIsInvalid() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_first_name = true;
    update.first_name = "   "; // trims to empty

    bool threw = false;
    try {
        users::UpdateProfile(store, 1, update, 1000);
    } catch (const domain::FirstNameInvalidError&) {
        threw = true;
    }
    Check(threw, "an empty (post-trim) first_name throws FirstNameInvalidError");
    Check(store.update_calls == 0, "no store write happens on validation failure");
}

void TestFirstNameOver64RunesIsInvalid() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_first_name = true;
    update.first_name = std::string(65, 'x');

    bool threw = false;
    try {
        users::UpdateProfile(store, 1, update, 1000);
    } catch (const domain::FirstNameInvalidError&) {
        threw = true;
    }
    Check(threw, "a 65-rune first_name exceeds the 64-rune limit");
}

void TestAboutOver70RunesIsInvalidForNonPremium() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_about = true;
    update.about = std::string(71, 'x');

    bool threw = false;
    try {
        users::UpdateProfile(store, 1, update, 1000);
    } catch (const domain::AboutTooLongError&) {
        threw = true;
    }
    Check(threw, "a 71-rune about exceeds the 70-rune limit for a non-premium account");
}

void TestPremiumAccountGetsLongerAboutLimit() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    u.premium_until = 2000; // active at now=1000
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_about = true;
    update.about = std::string(100, 'x'); // over the 70 non-premium limit, under 140

    const auto result = users::UpdateProfile(store, 1, update, 1000);
    Check(result.about.size() == 100, "a premium account may exceed the non-premium about limit");
}

void TestUtf8RunesAreCountedNotBytes() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.first_name = "Ada";
    store.Put(u);

    domain::UserProfileUpdate update;
    update.has_about = true;
    // 70 Cyrillic "п" characters -- 140 bytes (2 bytes/rune in UTF-8), but
    // exactly 70 runes, so this must NOT throw (a byte-count check would).
    std::string about;
    for (int i = 0; i < 70; ++i) about += "\xD0\xBF"; // U+043F CYRILLIC SMALL LETTER PE
    update.about = about;

    bool threw = false;
    try {
        users::UpdateProfile(store, 1, update, 1000);
    } catch (const domain::AboutTooLongError&) {
        threw = true;
    }
    Check(!threw, "the 70-rune limit counts codepoints, not UTF-8 bytes");
}

void TestUnknownUserThrowsUserNotFound() {
    FakeUserStore store; // empty
    domain::UserProfileUpdate update;
    bool threw = false;
    try {
        users::UpdateProfile(store, 999, update, 1000);
    } catch (const domain::UserNotFoundError&) {
        threw = true;
    }
    Check(threw, "an unknown user_id throws UserNotFoundError");
}

} // namespace

int main() {
    TestPartialUpdateOnlyChangesFlaggedFields();
    TestTrimsWhitespace();
    TestUnchangedUpdateSkipsStoreWrite();
    TestEmptyFirstNameIsInvalid();
    TestFirstNameOver64RunesIsInvalid();
    TestAboutOver70RunesIsInvalidForNonPremium();
    TestPremiumAccountGetsLongerAboutLimit();
    TestUtf8RunesAreCountedNotBytes();
    TestUnknownUserThrowsUserNotFound();
    if (g_failures == 0) {
        std::printf("all update_profile tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d update_profile test(s) failed\n", g_failures);
    return 1;
}
