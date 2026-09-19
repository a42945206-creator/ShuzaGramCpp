// Business-logic checks for users::UpdateBirthday (ported from
// Service.UpdateBirthday, internal/app/users/service.go:693), using the
// same fake-store pattern as the other tests in this directory.

#include <cstdio>
#include <string>
#include <unordered_map>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/users/update_birthday.hpp"

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
    domain::User UpdateProfile(std::int64_t, const std::string&, const std::string&, const std::string&) override {
        Unimplemented();
    }
    domain::User UpdateUsername(std::int64_t, const std::string&) override { Unimplemented(); }
    domain::User UpdatePhone(std::int64_t, const std::string&) override { Unimplemented(); }
    domain::User SetScamFake(std::int64_t, bool, bool) override { Unimplemented(); }
    std::vector<domain::User> SweepExpiredPremium(std::int64_t, int) override { Unimplemented(); }
    domain::User UpdateEmojiStatus(std::int64_t, const domain::UserEmojiStatus&) override { Unimplemented(); }
    domain::User UpdateBirthday(std::int64_t user_id, const domain::Birthday& birthday) override {
        ++update_calls;
        auto& u = by_id_.at(user_id);
        u.birthday = birthday;
        return u;
    }
    domain::User UpdatePersonalChannel(std::int64_t, std::int64_t) override { Unimplemented(); }
    domain::User UpdateColor(std::int64_t, bool, const domain::PeerColor&) override { Unimplemented(); }

    void Put(const domain::User& u) { by_id_[u.id] = u; }

    int update_calls = 0;

private:
    std::unordered_map<std::int64_t, domain::User> by_id_;
};

void TestSetsValidBirthday() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    store.Put(u);

    domain::Birthday b;
    b.day = 15;
    b.month = 6;
    b.year = 1990;
    const auto result = users::UpdateBirthday(store, 1, b);
    Check(result.birthday.day == 15 && result.birthday.month == 6 && result.birthday.year == 1990,
          "a valid birthday is stored as given");
    Check(store.update_calls == 1, "store is written exactly once");
}

void TestYearIsOptional() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    store.Put(u);

    domain::Birthday b;
    b.day = 1;
    b.month = 1; // no year
    const auto result = users::UpdateBirthday(store, 1, b);
    Check(result.birthday.year == 0, "a birthday without a year is valid and stored with year=0");
}

void TestZeroBirthdayClears() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    u.birthday = {15, 6, 1990};
    store.Put(u);

    const auto result = users::UpdateBirthday(store, 1, domain::Birthday{});
    Check(!result.birthday.IsSet(), "the zero birthday clears an existing one");
    Check(store.update_calls == 1, "clearing still writes to the store (no unchanged-shortcut in the Go source)");
}

void TestInvalidMonthThrows() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    store.Put(u);

    domain::Birthday b;
    b.day = 1;
    b.month = 13; // invalid
    bool threw = false;
    try {
        users::UpdateBirthday(store, 1, b);
    } catch (const domain::BirthdayInvalidError&) {
        threw = true;
    }
    Check(threw, "month 13 throws BirthdayInvalidError");
    Check(store.update_calls == 0, "no store write happens on validation failure");
}

void TestInvalidDayThrows() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    store.Put(u);

    domain::Birthday b;
    b.day = 32;
    b.month = 1;
    bool threw = false;
    try {
        users::UpdateBirthday(store, 1, b);
    } catch (const domain::BirthdayInvalidError&) {
        threw = true;
    }
    Check(threw, "day 32 throws BirthdayInvalidError");
}

void TestYearOutOfRangeThrows() {
    FakeUserStore store;
    domain::User u;
    u.id = 1;
    store.Put(u);

    domain::Birthday b;
    b.day = 1;
    b.month = 1;
    b.year = 1899; // below the 1900 floor
    bool threw = false;
    try {
        users::UpdateBirthday(store, 1, b);
    } catch (const domain::BirthdayInvalidError&) {
        threw = true;
    }
    Check(threw, "a year below 1900 throws BirthdayInvalidError");
}

void TestUnknownUserThrowsUserNotFound() {
    FakeUserStore store; // empty
    bool threw = false;
    try {
        users::UpdateBirthday(store, 999, domain::Birthday{});
    } catch (const domain::UserNotFoundError&) {
        threw = true;
    }
    Check(threw, "an unknown user_id throws UserNotFoundError");
}

} // namespace

int main() {
    TestSetsValidBirthday();
    TestYearIsOptional();
    TestZeroBirthdayClears();
    TestInvalidMonthThrows();
    TestInvalidDayThrows();
    TestYearOutOfRangeThrows();
    TestUnknownUserThrowsUserNotFound();
    if (g_failures == 0) {
        std::printf("all update_birthday tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d update_birthday test(s) failed\n", g_failures);
    return 1;
}
