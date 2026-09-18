#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "shuzagram/domain/user.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for the narrow auth.sendCode/auth.signIn/auth.signUp slice
// this round ports. Field order and type ids copied directly from
// /tmp/td-src/tg/tl_{auth_send_code,auth_sign_in,auth_sign_up,
// auth_sent_code,auth_sent_code_type,auth_authorization,code_settings}_gen.go,
// as with every other messages/ header in this project. See
// NOTES/auth-sign-in-plan.md for exactly what's deliberately not covered
// (email login, 2FA, real SMS/push code delivery, most of User's ~30
// optional fields).
namespace shuzagram::mtproto::messages {

// codeSettings#ad253d78 flags:# ... = CodeSettings;
//
// Every field is either a bare flag or optional data this project's dev-
// fixed-code path never reads (real push/SMS-provider hints). Decoded only
// far enough to consume exactly the right number of bytes, matching gotd/td's
// own DecodeBare byte-for-byte -- this is NOT a generic Bool decoder (see
// bool.hpp), just the minimum needed to skip codeSettings.app_sandbox.
struct CodeSettings {
    void DecodeBare(TLBuffer& b) {
        const std::uint32_t flags = b.Uint32();
        if (flags & (1u << 6)) { // logout_tokens
            const auto count = static_cast<std::size_t>(b.VectorHeader());
            for (std::size_t i = 0; i < count; ++i) (void)b.GetBytes();
        }
        if (flags & (1u << 8)) { // token
            (void)b.GetBytes(); // TL string is bytes-encoded on the wire
            // app_sandbox (bool) is gated by the SAME bit as token in the
            // upstream schema -- ported faithfully, not a typo. A TL Bool
            // is a bare 4-byte constructor id (boolTrue/boolFalse); its
            // value doesn't matter here, only skipping the right number of
            // bytes does.
            std::uint8_t discard[4];
            b.ConsumeN(discard, sizeof(discard));
        }
    }
};

// auth.sendCode#a677244f phone_number:string api_id:int api_hash:string
//   settings:CodeSettings = auth.SentCode;
struct AuthSendCodeRequest {
    static constexpr std::uint32_t kTypeId = 0xa677244f;
    std::string phone_number;
    int api_id = 0;
    std::string api_hash;

    void DecodeBare(TLBuffer& b) {
        phone_number = StringFromBytes(b.GetBytes());
        api_id = b.Int32();
        api_hash = StringFromBytes(b.GetBytes());
        CodeSettings settings;
        settings.DecodeBare(b);
    }

private:
    static std::string StringFromBytes(const std::vector<std::uint8_t>& v) { return {v.begin(), v.end()}; }
};

// auth.signIn#8d52a951 flags:# phone_number:string phone_code_hash:string
//   phone_code:flags.0?string email_verification:flags.1?EmailVerification
//   = auth.Authorization;
//
// email_verification (flags bit 1) is not decoded: this slice only supports
// the plain SMS/app-code path. A request that sets it throws
// domain::NotImplementedError rather than silently misparsing the buffer.
struct AuthSignInRequest {
    static constexpr std::uint32_t kTypeId = 0x8d52a951;
    std::string phone_number;
    std::string phone_code_hash;
    std::string phone_code;

    void DecodeBare(TLBuffer& b) {
        const std::uint32_t flags = b.Uint32();
        phone_number = StringFromBytes(b.GetBytes());
        phone_code_hash = StringFromBytes(b.GetBytes());
        if (flags & (1u << 0)) phone_code = StringFromBytes(b.GetBytes());
        if (flags & (1u << 1)) {
            throw domain::NotImplementedError("auth.signIn with email_verification");
        }
    }

private:
    static std::string StringFromBytes(const std::vector<std::uint8_t>& v) { return {v.begin(), v.end()}; }
};

// auth.signUp#aac7b717 flags:# no_joined_notifications:flags.0?true
//   phone_number:string phone_code_hash:string first_name:string
//   last_name:string = auth.Authorization;
struct AuthSignUpRequest {
    static constexpr std::uint32_t kTypeId = 0xaac7b717;
    std::string phone_number;
    std::string phone_code_hash;
    std::string first_name;
    std::string last_name;

    void DecodeBare(TLBuffer& b) {
        (void)b.Uint32(); // flags: no_joined_notifications carries no data of its own
        phone_number = StringFromBytes(b.GetBytes());
        phone_code_hash = StringFromBytes(b.GetBytes());
        first_name = StringFromBytes(b.GetBytes());
        last_name = StringFromBytes(b.GetBytes());
    }

private:
    static std::string StringFromBytes(const std::vector<std::uint8_t>& v) { return {v.begin(), v.end()}; }
};

// authSentCodeTypeApp#3dbb5986 length:int = auth.SentCodeType;
struct AuthSentCodeTypeApp {
    static constexpr std::uint32_t kTypeId = 0x3dbb5986;
    int length = 0;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt32(length);
    }
};

// auth.sentCode#5e002502 flags:# type:auth.SentCodeType phone_code_hash:string
//   next_type:flags.1?auth.CodeType timeout:flags.2?int = auth.SentCode;
//
// next_type/timeout are never set by this slice (flags = 0): there is no
// resendCode implementation yet to advertise a next type for.
struct AuthSentCode {
    static constexpr std::uint32_t kTypeId = 0x5e002502;
    int code_length = 0;
    std::string phone_code_hash;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutUint32(0); // flags
        AuthSentCodeTypeApp type;
        type.length = code_length;
        type.Encode(b);
        b.PutBytes(std::vector<std::uint8_t>(phone_code_hash.begin(), phone_code_hash.end()));
    }
};

// auth.authorizationSignUpRequired#44747e9a flags:# terms_of_service:flags.0?help.TermsOfService = auth.Authorization;
struct AuthAuthorizationSignUpRequired {
    static constexpr std::uint32_t kTypeId = 0x44747e9a;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutUint32(0); // flags: no terms_of_service in this slice
    }
};

// Minimal user#b1b8cc83 encoder: only the fields a freshly-authorized
// client actually needs to render itself (self=true, id, access_hash,
// first_name, optionally last_name/phone). None of the ~25 other optional
// fields (photo, status, premium, emoji_status, usernames, color, ...) are
// populated -- see NOTES/auth-sign-in-plan.md. Encode-only: this project
// never needs to decode a User from the wire.
struct MinimalSelfUser {
    static constexpr std::uint32_t kTypeId = 0xb1b8cc83;
    domain::User user;

    void Encode(TLBuffer& b) const {
        std::uint32_t flags = 0;
        constexpr std::uint32_t kFlagAccessHash = 1u << 0;
        constexpr std::uint32_t kFlagFirstName = 1u << 1;
        constexpr std::uint32_t kFlagLastName = 1u << 2;
        constexpr std::uint32_t kFlagPhone = 1u << 4;
        constexpr std::uint32_t kFlagSelf = 1u << 10;
        flags |= kFlagSelf;
        flags |= kFlagAccessHash;
        if (!user.first_name.empty()) flags |= kFlagFirstName;
        if (!user.last_name.empty()) flags |= kFlagLastName;
        if (!user.phone.empty()) flags |= kFlagPhone;

        b.PutID(kTypeId);
        b.PutUint32(flags);
        b.PutUint32(0); // flags2: nothing in this slice sets a flags2 field
        b.PutLong(user.id);
        b.PutLong(user.access_hash);
        if (flags & kFlagFirstName) b.PutBytes(ToBytes(user.first_name));
        if (flags & kFlagLastName) b.PutBytes(ToBytes(user.last_name));
        if (flags & kFlagPhone) b.PutBytes(ToBytes(user.phone));
    }

private:
    static std::vector<std::uint8_t> ToBytes(const std::string& s) { return {s.begin(), s.end()}; }
};

// auth.authorization#2ea2c0d4 flags:# setup_password_required:flags.1?true
//   otherwise_relogin_days:flags.1?int tmp_sessions:flags.0?int
//   future_auth_token:flags.2?bytes user:User = auth.Authorization;
struct AuthAuthorization {
    static constexpr std::uint32_t kTypeId = 0x2ea2c0d4;
    domain::User user;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutUint32(0); // flags: none of the 2FA/tmp-session/future-token fields apply here
        MinimalSelfUser wrapped;
        wrapped.user = user;
        wrapped.Encode(b);
    }
};

} // namespace shuzagram::mtproto::messages
