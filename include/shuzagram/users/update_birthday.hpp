#pragma once

#include <cstdint>

#include "shuzagram/domain/user.hpp"
#include "shuzagram/store/user_store.hpp"

// Faithful port of Service.UpdateBirthday (internal/app/users/service.go:693).
namespace shuzagram::users {

// The zero Birthday (IsSet() == false) clears it -- normalized here exactly
// like the Go source, even if the caller sent a partially-set, not-yet-
// invalid value (e.g. day/month zero with a stray year). A non-empty
// birthday that fails domain::ValidBirthday throws
// domain::BirthdayInvalidError. Throws domain::UserNotFoundError if user_id
// is 0 or doesn't name a live user.
domain::User UpdateBirthday(store::IUserStore& users, std::int64_t user_id, domain::Birthday birthday);

} // namespace shuzagram::users
