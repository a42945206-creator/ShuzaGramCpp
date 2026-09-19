#pragma once

#include <cstdint>
#include <string>

#include "shuzagram/domain/user.hpp"
#include "shuzagram/store/user_store.hpp"

// Faithful port of the username slice of (internal/app/users/service.go):
// Service.CheckUsername/UpdateUsername plus their shared
// normalizeUsername/validUsername/checkUsernameAvailable helpers. See
// NOTES/account-username-plan.md for what's cut (the batch
// usernameAvailabilityStore fast path -- this port only has the plain
// ByUsername fallback the Go source itself falls back to).
namespace shuzagram::users {

// TrimSpace, then strip a leading '@', then TrimSpace again -- exactly
// Go's normalizeUsername, not the (slightly different-order, ASCII-only)
// TrimUsername already private to store/postgres/user_store.cpp.
std::string NormalizeUsername(const std::string& username);

// 5..32 chars, first char a letter, remaining chars letters/digits/'_'.
// Mirrors validUsername exactly (byte-wise ASCII check, not rune-aware --
// same as the Go source, which only ever accepts basic Latin usernames).
bool ValidUsername(const std::string& username);

// Mirrors CheckUsername: throws domain::UserNotFoundError if user_id is 0
// or doesn't name a live user, domain::UsernameInvalidError if the
// normalized username fails ValidUsername (including when it's empty --
// unlike UpdateUsername, CheckUsername never treats "" as a valid answer).
bool CheckUsername(store::IUserStore& users, std::int64_t user_id, const std::string& username);

// Mirrors UpdateUsername: "" clears the username (no validation is run on
// an intentional clear). A non-empty username is normalized, validated
// (domain::UsernameInvalidError) and checked for availability
// (domain::UsernameOccupiedError) before being written. A no-op update (the
// normalized value already matches the caller's current username) returns
// the caller unchanged without touching the store.
domain::User UpdateUsername(store::IUserStore& users, std::int64_t user_id, const std::string& username);

} // namespace shuzagram::users
