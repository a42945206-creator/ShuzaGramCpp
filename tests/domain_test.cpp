// Lightweight assert-based checks (no test framework dependency for this
// slice). Phone cases are ported 1:1 from
// internal/domain/phone_identity_test.go to confirm libphonenumber agrees
// with the Go nyaruka/phonenumbers port, which is built on the same
// underlying Google metadata.

#include <cstdio>
#include <cstdlib>
#include <string>

#include "shuzagram/domain/phone.hpp"
#include "shuzagram/domain/user.hpp"

namespace {

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

void CheckEq(const std::string& got, const std::string& want, const std::string& what) {
    Check(got == want, what + " (got \"" + got + "\", want \"" + want + "\")");
}

void TestNormalizePhoneCountryAware() {
    using shuzagram::domain::NormalizePhone;
    using shuzagram::domain::kOfficialSystemPhone;
    CheckEq(NormalizePhone("+98 0998 167 9461"), "989981679461", "iran redundant national trunk");
    CheckEq(NormalizePhone("+98 998 167 9461"), "989981679461", "iran canonical");
    CheckEq(NormalizePhone("9809981679461"), "989981679461", "iran wire digits redundant trunk");
    CheckEq(NormalizePhone("+39 02 1234 5678"), "390212345678", "italy significant leading zero");
    CheckEq(NormalizePhone("+86 (188) 0000-0000"), "8618800000000", "china presentation");
    CheckEq(NormalizePhone("+1 555 000 0001"), "15550000001", "possible reserved NANP range");
    CheckEq(NormalizePhone("09981679461"), "", "local number without country");
    CheckEq(NormalizePhone("+98abc9981679461"), "", "letters are not separators");
    CheckEq(NormalizePhone("00989981679461"), "", "international prefix is not country code");
    CheckEq(NormalizePhone(kOfficialSystemPhone), kOfficialSystemPhone, "reserved system identity");
}

void TestNormalizePhoneVirtual888() {
    using shuzagram::domain::NormalizePhone;
    CheckEq(NormalizePhone("+888 12-34"), "8881234", "virtual 888 short");
    CheckEq(NormalizePhone("8880000"), "8880000", "virtual 888 no plus");
    CheckEq(NormalizePhone("888123456789012"), "888123456789012", "virtual 888 max length");
    for (const std::string& phone : {std::string("888123"), std::string("8881234567890123"),
                                      std::string("+888abc1234")}) {
        CheckEq(NormalizePhone(phone), "", "virtual 888 rejects: " + phone);
    }
}

void TestValidPhoneCanonicalShape() {
    using shuzagram::domain::ValidPhone;
    using shuzagram::domain::kOfficialSystemPhone;
    for (const std::string& phone :
         {std::string("989981679461"), std::string("390212345678"), std::string("8618800000000"),
          std::string("15550000001"), std::string("8880000"), std::string("888123456789012"),
          std::string(kOfficialSystemPhone)}) {
        Check(ValidPhone(phone), "ValidPhone should accept canonical: " + phone);
    }
    for (const std::string& phone :
         {std::string("+989981679461"), std::string("+8881234"), std::string("888123"),
          std::string("8881234567890123"), std::string("9809981679461"), std::string("09981679461"),
          std::string(""), std::string("+98abc9981679461")}) {
        Check(!ValidPhone(phone), "ValidPhone should reject: " + phone);
    }
}

void TestUserPremiumAndEmojiStatus() {
    using namespace shuzagram::domain;
    User u;
    u.premium_until = 1000;
    Check(u.PremiumActiveAt(500), "premium active before expiry");
    Check(!u.PremiumActiveAt(1000), "premium not active exactly at expiry");
    Check(!u.PremiumActiveAt(1500), "premium not active after expiry");

    u.bot = true;
    Check(!u.PremiumActiveAt(500), "bots are never premium");
    u.bot = false;

    u.emoji_status_document_id = 42;
    u.emoji_status_until = 0; // permanent
    Check(u.EmojiStatusActiveAt(500), "permanent emoji status active while premium");
    u.premium_until = 100;
    Check(!u.EmojiStatusActiveAt(500), "emoji status inactive once premium lapses");
}

void TestApproximateUserStatusBuckets() {
    using namespace shuzagram::domain;
    Check(ApproximateUserStatus(0, 1000).kind == UserStatusKind::Recently, "zero last_seen -> recently");
    const int now = 2'000'000'000; // large enough that every offset below stays positive

    Check(ApproximateUserStatus(now - 60, now).kind == UserStatusKind::Recently, "1 min ago -> recently");
    Check(ApproximateUserStatus(now - 5 * 24 * 60 * 60, now).kind == UserStatusKind::LastWeek,
          "5 days ago -> last week");
    Check(ApproximateUserStatus(now - 20 * 24 * 60 * 60, now).kind == UserStatusKind::LastMonth,
          "20 days ago -> last month");
    Check(ApproximateUserStatus(now - 400 * 24 * 60 * 60, now).kind == UserStatusKind::Empty,
          "over a year ago -> empty");
}

void TestBirthdayValidation() {
    using namespace shuzagram::domain;
    Check(ValidBirthday(Birthday{15, 6, 2000}), "valid full birthday");
    Check(ValidBirthday(Birthday{15, 6, 0}), "valid birthday without year");
    Check(ValidBirthday(Birthday{31, 4, 0}), "april 31st is accepted -- only day/month range is checked");
    Check(!ValidBirthday(Birthday{1, 13, 0}), "month 13 invalid");
    Check(!ValidBirthday(Birthday{0, 6, 0}), "day 0 invalid");
    Check(!ValidBirthday(Birthday{15, 6, 1899}), "year below range invalid");
    Check(Birthday{}.IsSet() == false, "zero birthday is not set");
    Check(Birthday{15, 6, 0}.IsSet(), "day+month birthday is set");
}

void TestDeletedTombstoneStripsFields() {
    using namespace shuzagram::domain;
    User u;
    u.id = 7;
    u.access_hash = 123;
    u.first_name = "Alice";
    u.phone = "15550000001";
    u.deleted = true;
    u.deleted_at = 999;
    u.deletion_source = AccountDeletionSource::Manual;

    const User tomb = u.DeletedTombstone();
    Check(tomb.id == 7, "tombstone keeps id");
    Check(tomb.access_hash == 123, "tombstone keeps access_hash");
    Check(tomb.first_name.empty(), "tombstone strips first_name");
    Check(tomb.phone.empty(), "tombstone strips phone");
    Check(tomb.deleted_at == 999, "tombstone keeps deleted_at");
    Check(tomb.status.kind == UserStatusKind::Empty, "tombstone status is empty");
}

} // namespace

int main() {
    TestNormalizePhoneCountryAware();
    TestNormalizePhoneVirtual888();
    TestValidPhoneCanonicalShape();
    TestUserPremiumAndEmojiStatus();
    TestApproximateUserStatusBuckets();
    TestBirthdayValidation();
    TestDeletedTombstoneStripsFields();

    if (g_failures == 0) {
        std::printf("all domain tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d domain test(s) failed\n", g_failures);
    return 1;
}
