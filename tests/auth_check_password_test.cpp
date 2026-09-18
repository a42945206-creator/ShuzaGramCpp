// Validation-logic checks for auth::GetPassword/CheckPassword, using a
// simple in-memory fake of IPasswordStore. The SRP math itself is already
// verified against gotd/td's official vector in mtproto_srp_test.cpp; this
// file exercises the surrounding business logic (which errors fire in
// which order, how GetPassword rolls/persists a challenge) using a
// genuine client-side SrpClientProof to build real proofs, not
// hand-crafted byte strings.

#include <cstdio>
#include <map>
#include <string>

#include "shuzagram/auth/check_password.hpp"
#include "shuzagram/mtproto/crypto/srp.hpp"

namespace {

using namespace shuzagram;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

std::vector<std::uint8_t> Ascii(const std::string& s) { return {s.begin(), s.end()}; }

class FakePasswordStore final : public store::IPasswordStore {
public:
    std::optional<domain::PasswordSettings> GetByUser(std::int64_t user_id) override {
        const auto it = rows_.find(user_id);
        return it == rows_.end() ? std::nullopt : std::optional(it->second);
    }
    void Save(std::int64_t user_id, const domain::PasswordSettings& settings) override { rows_[user_id] = settings; }

private:
    std::map<std::int64_t, domain::PasswordSettings> rows_;
};

// Seeds a real, self-consistent password row for `password` (mirrors the
// "test fixture recipe" for directly inserting an account_passwords row --
// see NOTES/auth-check-password-plan.md).
void SeedPassword(FakePasswordStore& store, std::int64_t user_id, const std::vector<std::uint8_t>& password) {
    domain::PasswordSettings settings = auth::DefaultPasswordSettings();
    std::vector<std::uint8_t> salt1 = {0xEC, 0xF8, 0x73, 0x76, 0x65, 0xBC, 0x77, 0x5A}; // baseSalt1
    for (int i = 0; i < 32; ++i) salt1.push_back(static_cast<std::uint8_t>(i + 1));
    const auto salt2 = mtproto::crypto::SrpBaseSalt2();

    domain::PasswordAlgo algo;
    algo.salt1 = salt1;
    algo.salt2 = salt2;
    algo.g = mtproto::crypto::kSrpBaseG;
    algo.p = mtproto::crypto::SrpBaseP();

    settings.has_password = true;
    settings.current_algo = algo;
    settings.srp_verifier = mtproto::crypto::SrpComputeVerifier(password, salt1, salt2);
    store.Save(user_id, settings);
}

void TestNoPasswordAcceptsEmptyCheck() {
    FakePasswordStore store;
    domain::PasswordCheck check;
    check.empty = true;
    auth::CheckPassword(store, /*user_id=*/1, check); // should not throw
    Check(true, "CheckPassword accepts inputCheckPasswordEmpty for an account with no password");
}

void TestNoPasswordRejectsSrpCheck() {
    FakePasswordStore store;
    domain::PasswordCheck check;
    check.empty = false;
    check.srp_id = 1;
    check.a = {1, 2, 3};
    check.m1 = {4, 5, 6};
    try {
        auth::CheckPassword(store, /*user_id=*/1, check);
        Check(false, "an SRP proof against a passwordless account should throw");
    } catch (const auth::PasswordHashInvalidError&) {
        Check(true, "CheckPassword rejects an SRP proof for an account with no password");
    }
}

void TestHasPasswordRejectsEmptyCheck() {
    FakePasswordStore store;
    SeedPassword(store, 2, Ascii("correct horse"));
    domain::PasswordCheck check;
    check.empty = true;
    try {
        auth::CheckPassword(store, 2, check);
        Check(false, "inputCheckPasswordEmpty against a password-protected account should throw");
    } catch (const auth::PasswordHashInvalidError&) {
        Check(true, "CheckPassword rejects inputCheckPasswordEmpty for an account WITH a password");
    }
}

void TestHasPasswordWithSrpIdZeroIsSrpIdInvalid() {
    FakePasswordStore store;
    SeedPassword(store, 3, Ascii("hunter2"));
    // No GetPassword call happened yet, so srp_id is still its zero
    // "unassigned" sentinel -- the Go source's checkSRP checks
    // srp_id != 0 BEFORE checking whether a challenge was ever rolled, so
    // this is SRP_ID_INVALID, not SRP_PASSWORD_CHANGED (see
    // TestHasPasswordWithChallengeGoneIsPasswordChanged for that case).
    domain::PasswordCheck check;
    check.srp_id = 1;
    check.a = {1};
    check.m1 = {2};
    try {
        auth::CheckPassword(store, 3, check);
        Check(false, "checking a password whose srp_id was never assigned should throw");
    } catch (const auth::SrpIdInvalidError&) {
        Check(true, "CheckPassword throws SrpIdInvalidError when srp_id is still the zero sentinel");
    }
}

void TestHasPasswordWithChallengeGoneIsPasswordChanged() {
    FakePasswordStore store;
    SeedPassword(store, 5, Ascii("hunter2"));
    // A real srp_id was assigned (e.g. by an earlier GetPassword call),
    // but srp_b_secret/srp_b are empty -- the challenge that srp_id
    // belonged to is gone (matches a password change clearing them).
    auto settings = *store.GetByUser(5);
    settings.srp_id = 777;
    store.Save(5, settings);

    domain::PasswordCheck check;
    check.srp_id = 777;
    check.a = {1};
    check.m1 = {2};
    try {
        auth::CheckPassword(store, 5, check);
        Check(false, "checking a password with a valid srp_id but no live challenge should throw");
    } catch (const auth::SrpPasswordChangedError&) {
        Check(true, "CheckPassword throws SrpPasswordChangedError when the challenge itself is missing");
    }
}

void TestFullRoundTripSucceeds() {
    FakePasswordStore store;
    const auto password = Ascii("correct horse battery staple");
    SeedPassword(store, 4, password);

    const auto settings_before = *store.GetByUser(4);
    const auto after_get = auth::GetPassword(store, 4);
    Check(after_get.srp_id != 0, "GetPassword assigns a nonzero srp_id");
    Check(!after_get.srp_b.empty() && !after_get.srp_b_secret.empty(), "GetPassword rolls a live SRP challenge");
    Check(after_get.current_algo.has_value(), "GetPassword's response carries the current algo/salts");

    const auto persisted = *store.GetByUser(4);
    Check(persisted.srp_b == after_get.srp_b && persisted.srp_id == after_get.srp_id,
          "GetPassword persists the rolled challenge (a second GetByUser sees it)");

    const auto client_random = std::vector<std::uint8_t>(256, 0x07);
    const auto proof = mtproto::crypto::SrpClientProof(password, after_get.current_algo->salt1,
                                                        after_get.current_algo->salt2, after_get.srp_b, client_random);

    domain::PasswordCheck check;
    check.srp_id = after_get.srp_id;
    check.a = proof.a;
    check.m1 = proof.m1;
    auth::CheckPassword(store, 4, check); // should not throw
    Check(true, "CheckPassword accepts a genuine client proof built from a real GetPassword challenge");

    // Wrong srp_id.
    domain::PasswordCheck wrong_id_check = check;
    wrong_id_check.srp_id = check.srp_id + 1;
    try {
        auth::CheckPassword(store, 4, wrong_id_check);
        Check(false, "a mismatched srp_id should throw");
    } catch (const auth::SrpIdInvalidError&) {
        Check(true, "CheckPassword throws SrpIdInvalidError for a mismatched srp_id");
    }

    // Wrong M1 (right srp_id/A, tampered proof).
    domain::PasswordCheck wrong_m1_check = check;
    wrong_m1_check.m1.back() ^= 0x01;
    try {
        auth::CheckPassword(store, 4, wrong_m1_check);
        Check(false, "a tampered M1 should throw");
    } catch (const auth::PasswordHashInvalidError&) {
        Check(true, "CheckPassword throws PasswordHashInvalidError for a tampered M1");
    }

    (void)settings_before;
}

} // namespace

int main() {
    TestNoPasswordAcceptsEmptyCheck();
    TestNoPasswordRejectsSrpCheck();
    TestHasPasswordRejectsEmptyCheck();
    TestHasPasswordWithSrpIdZeroIsSrpIdInvalid();
    TestHasPasswordWithChallengeGoneIsPasswordChanged();
    TestFullRoundTripSucceeds();
    if (g_failures == 0) {
        std::printf("all auth::GetPassword/CheckPassword tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d auth::GetPassword/CheckPassword test(s) failed\n", g_failures);
    return 1;
}
