#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "shuzagram/domain/password.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for the auth.checkPassword / account.getPassword slice.
// Field order and type ids copied directly from
// /tmp/td-src/tg/tl_{account_password,password_kdf_algo,
// input_check_password_srp,account_get_password,auth_check_password}_gen.go,
// as with every other messages/ header in this project. See
// NOTES/auth-check-password-plan.md for what's deliberately not covered
// (account.updatePasswordSettings, Passport secure values, login email).
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kPasswordKdfAlgoModPowTypeId = 0x3a912d4a;
inline constexpr std::uint32_t kPasswordKdfAlgoUnknownTypeId = 0xd45ab096;
inline constexpr std::uint32_t kSecurePasswordKdfAlgoUnknownTypeId = 0x004a8537;

// passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow#3a912d4a
//   salt1:bytes salt2:bytes g:int p:bytes = PasswordKdfAlgo;
// passwordKdfAlgoUnknown#d45ab096 = PasswordKdfAlgo;
//
// Encodes as Unknown whenever algo.p is empty (this project's stand-in for
// "no algo configured yet", matching the Go source's own tgPasswordAlgo).
inline void EncodePasswordAlgo(TLBuffer& b, const domain::PasswordAlgo& algo) {
    if (algo.p.empty()) {
        b.PutID(kPasswordKdfAlgoUnknownTypeId);
        return;
    }
    b.PutID(kPasswordKdfAlgoModPowTypeId);
    b.PutBytes(algo.salt1);
    b.PutBytes(algo.salt2);
    b.PutInt32(algo.g);
    b.PutBytes(algo.p);
}

// secure_password_kdf_algo_unknown#4a8537 = SecurePasswordKdfAlgo;
//
// This project never sets up Telegram Passport secure values, so
// new_secure_algo is always this "unset" variant.
inline void EncodeSecurePasswordAlgoUnknown(TLBuffer& b) { b.PutID(kSecurePasswordKdfAlgoUnknownTypeId); }

// account.password#957b50fb flags:# has_recovery:flags.0?true
//   has_secure_values:flags.1?true current_algo:flags.2?PasswordKdfAlgo
//   srp_B:flags.2?bytes srp_id:flags.2?long hint:flags.3?string
//   email_unconfirmed_pattern:flags.4?string new_algo:PasswordKdfAlgo
//   new_secure_algo:SecurePasswordKdfAlgo secure_random:bytes
//   pending_reset_date:flags.5?int login_email_pattern:flags.6?string
//   = account.Password;
//
// Flag bit 2 gates current_algo/srp_B/srp_id TOGETHER -- it doubles as
// "has_password" (their presence in the response is exactly how a client
// knows a password exists at all).
struct AccountPassword {
    static constexpr std::uint32_t kTypeId = 0x957b50fb;
    domain::PasswordSettings settings;

    void Encode(TLBuffer& b) const {
        constexpr std::uint32_t kFlagHasRecovery = 1u << 0;
        constexpr std::uint32_t kFlagHasSecureValues = 1u << 1;
        constexpr std::uint32_t kFlagHasPassword = 1u << 2;
        constexpr std::uint32_t kFlagHint = 1u << 3;

        std::uint32_t flags = 0;
        if (settings.has_recovery) flags |= kFlagHasRecovery;
        if (settings.has_secure_values) flags |= kFlagHasSecureValues;
        if (settings.has_password) flags |= kFlagHasPassword;
        if (!settings.hint.empty()) flags |= kFlagHint;

        b.PutID(kTypeId);
        b.PutUint32(flags);
        if (settings.has_password) {
            EncodePasswordAlgo(b, settings.current_algo.value_or(settings.new_algo));
            b.PutBytes(settings.srp_b);
            b.PutLong(settings.srp_id);
        }
        if (!settings.hint.empty()) b.PutBytes(ToBytes(settings.hint));
        // email_unconfirmed_pattern (bit 4): never set -- no email-login flow.
        EncodePasswordAlgo(b, settings.new_algo);
        EncodeSecurePasswordAlgoUnknown(b);
        b.PutBytes(settings.secure_random);
        // pending_reset_date (bit 5), login_email_pattern (bit 6): never set.
    }

private:
    static std::vector<std::uint8_t> ToBytes(const std::string& s) { return {s.begin(), s.end()}; }
};

// account.getPassword#548a30f5 = account.Password;
struct AccountGetPasswordRequest {
    static constexpr std::uint32_t kTypeId = 0x548a30f5;
    void DecodeBare(TLBuffer&) const {} // no fields
};

// auth.checkPassword#d18b4d16 password:InputCheckPasswordSRP = auth.Authorization;
//
// inputCheckPasswordEmpty#9880f658 = InputCheckPasswordSRP;
// inputCheckPasswordSRP#d27ff082 srp_id:long A:bytes M1:bytes = InputCheckPasswordSRP;
struct AuthCheckPasswordRequest {
    static constexpr std::uint32_t kTypeId = 0xd18b4d16;
    domain::PasswordCheck check;

    void DecodeBare(TLBuffer& b) {
        static constexpr std::uint32_t kInputCheckPasswordEmptyTypeId = 0x9880f658;
        static constexpr std::uint32_t kInputCheckPasswordSrpTypeId = 0xd27ff082;

        const std::uint32_t id = b.PeekID();
        if (id == kInputCheckPasswordEmptyTypeId) {
            b.ConsumeID(id);
            check = domain::PasswordCheck{};
            check.empty = true;
            return;
        }
        b.ConsumeID(kInputCheckPasswordSrpTypeId); // throws UnexpectedIdError for anything else
        check = domain::PasswordCheck{};
        check.srp_id = b.Long();
        check.a = b.GetBytes();
        check.m1 = b.GetBytes();
    }
};

} // namespace shuzagram::mtproto::messages
