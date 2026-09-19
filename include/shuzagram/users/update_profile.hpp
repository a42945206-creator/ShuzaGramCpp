#pragma once

#include <cstdint>

#include "shuzagram/domain/user.hpp"
#include "shuzagram/store/user_store.hpp"

// Faithful port of (internal/app/users/service.go).Service.UpdateProfile --
// the SERVICE layer that gives account.updateProfile's independently
// optional first_name/last_name/about fields their partial-update meaning.
// The store method underneath (IUserStore::UpdateProfile) always overwrites
// all three fields, exactly like the real store.UserStore.UpdateProfile --
// merging in the caller's current values for any field left unset is this
// function's whole job, same split as the Go source.
namespace shuzagram::users {

// now is a Unix-second clock reading, needed only to evaluate the caller's
// premium status for the about-length limit (premium gets a longer limit).
//
// Throws domain::UserNotFoundError if user_id doesn't name a live user,
// domain::FirstNameInvalidError if the resulting first_name is empty or
// either name exceeds 64 runes, domain::AboutTooLongError if about exceeds
// 70 runes (140 for a premium account).
domain::User UpdateProfile(store::IUserStore& users, std::int64_t user_id,
                            const domain::UserProfileUpdate& update, std::int64_t now);

} // namespace shuzagram::users
