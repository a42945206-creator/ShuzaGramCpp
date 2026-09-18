#include "shuzagram/auth/check_password.hpp"

#include <cstring>

#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/srp.hpp"

// Ported from internal/app/account/service.go + srp.go -- see the header
// for exact scope.
namespace shuzagram::auth {

namespace {

std::vector<std::uint8_t> DefaultSecureRandom() {
    static const std::string kValue = "telesrv-tdesktop-dev-secure-rand";
    return {kValue.begin(), kValue.end()};
}

domain::PasswordSettings NormalizePasswordSettings(domain::PasswordSettings settings) {
    if (settings.secure_random.empty()) settings.secure_random = DefaultSecureRandom();
    if (settings.new_algo.p.empty()) settings.new_algo = DefaultPasswordAlgo();
    if (settings.has_password && !settings.current_algo) settings.current_algo = settings.new_algo;
    return settings;
}

domain::PasswordSettings LoadNormalized(store::IPasswordStore& passwords, std::int64_t user_id) {
    const auto found = passwords.GetByUser(user_id);
    return NormalizePasswordSettings(found.value_or(DefaultPasswordSettings()));
}

void CheckSrp(const domain::PasswordSettings& settings, const domain::PasswordCheck& check) {
    if (check.empty) {
        // inputCheckPasswordEmpty is only a valid proof for an account
        // that genuinely has no password.
        if (settings.has_password) throw PasswordHashInvalidError();
        return;
    }
    if (!settings.has_password) throw PasswordHashInvalidError();
    if (settings.srp_id == 0 || settings.srp_id != check.srp_id) throw SrpIdInvalidError();
    if (settings.srp_verifier.empty() || settings.srp_b_secret.empty() || settings.srp_b.empty()) {
        // The account has a password, but no live challenge -- either
        // GetPassword was never called, or the password changed after it
        // was (which clears these on a real "set new password" flow, not
        // otherwise ported by this project, but the check stays correct
        // regardless of how they became empty).
        throw SrpPasswordChangedError();
    }

    const auto& salt1 = settings.current_algo ? settings.current_algo->salt1 : settings.new_algo.salt1;
    std::vector<std::uint8_t> expected_m1;
    try {
        expected_m1 =
            mtproto::crypto::SrpCalcM1(salt1, settings.srp_verifier, settings.srp_b_secret, settings.srp_b, check.a);
    } catch (const std::exception&) {
        // A or the verifier out of range, or u == 0 -- collapse into the
        // same public error as a genuine wrong-proof mismatch (never
        // reveal which internal check failed).
        throw PasswordHashInvalidError();
    }
    if (expected_m1 != check.m1) throw PasswordHashInvalidError();
}

} // namespace

domain::PasswordAlgo DefaultPasswordAlgo() {
    domain::PasswordAlgo algo;
    algo.salt1 = {0xEC, 0xF8, 0x73, 0x76, 0x65, 0xBC, 0x77, 0x5A}; // baseSalt1
    algo.salt2 = mtproto::crypto::SrpBaseSalt2();
    algo.g = mtproto::crypto::kSrpBaseG;
    algo.p = mtproto::crypto::SrpBaseP();
    return algo;
}

domain::PasswordSettings DefaultPasswordSettings() {
    domain::PasswordSettings settings;
    settings.secure_random = DefaultSecureRandom();
    settings.new_algo = DefaultPasswordAlgo();
    return settings;
}

domain::PasswordSettings GetPassword(store::IPasswordStore& passwords, std::int64_t user_id) {
    domain::PasswordSettings settings = LoadNormalized(passwords, user_id);
    if (!settings.has_password) return settings;

    const auto challenge = mtproto::crypto::SrpMakeChallenge(settings.srp_verifier);
    settings.srp_b_secret = challenge.b_secret;
    settings.srp_b = challenge.b;
    if (settings.srp_id == 0) {
        const auto random_bytes = mtproto::crypto::SystemRandomBytes(8);
        std::int64_t id;
        std::memcpy(&id, random_bytes.data(), 8);
        // srp_id must never be the sentinel "unassigned" value -- redraw
        // in the (astronomically unlikely) case a real random draw is 0.
        settings.srp_id = id != 0 ? id : 1;
    }
    passwords.Save(user_id, settings);
    return settings;
}

void CheckPassword(store::IPasswordStore& passwords, std::int64_t user_id, const domain::PasswordCheck& check) {
    const domain::PasswordSettings settings = LoadNormalized(passwords, user_id);
    CheckSrp(settings, check);
}

} // namespace shuzagram::auth
