#pragma once

#include <string_view>

// Faithful port of the enum in internal/domain/account_deletion.go. Only the
// source enum is ported here; deletion-flow orchestration lives with the
// account-lifecycle module and is ported separately.
namespace shuzagram::domain {

enum class AccountDeletionSource {
    None, // zero value: account is not deleted
    Manual,
    ForgotPassword,
    TOSDecline,
    PasswordResetExpiry,
    AccountTTL,
    FreezeExpiry,
};

constexpr std::string_view ToString(AccountDeletionSource source) {
    switch (source) {
        case AccountDeletionSource::None: return "";
        case AccountDeletionSource::Manual: return "manual";
        case AccountDeletionSource::ForgotPassword: return "forgot_password";
        case AccountDeletionSource::TOSDecline: return "tos_decline";
        case AccountDeletionSource::PasswordResetExpiry: return "password_reset_expiry";
        case AccountDeletionSource::AccountTTL: return "account_ttl";
        case AccountDeletionSource::FreezeExpiry: return "freeze_expiry";
    }
    return "";
}

constexpr AccountDeletionSource AccountDeletionSourceFromString(std::string_view s) {
    if (s == "manual") return AccountDeletionSource::Manual;
    if (s == "forgot_password") return AccountDeletionSource::ForgotPassword;
    if (s == "tos_decline") return AccountDeletionSource::TOSDecline;
    if (s == "password_reset_expiry") return AccountDeletionSource::PasswordResetExpiry;
    if (s == "account_ttl") return AccountDeletionSource::AccountTTL;
    if (s == "freeze_expiry") return AccountDeletionSource::FreezeExpiry;
    return AccountDeletionSource::None;
}

} // namespace shuzagram::domain
