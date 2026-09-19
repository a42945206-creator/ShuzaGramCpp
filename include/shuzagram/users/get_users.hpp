#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "shuzagram/domain/user.hpp"
#include "shuzagram/mtproto/messages/users.hpp"
#include "shuzagram/store/authorization_store.hpp"
#include "shuzagram/store/user_store.hpp"

// Faithful, scoped port of onUsersGetUsers (internal/rpc/users.go). See
// NOTES/users-get-users-plan.md for what's cut relative to the Go source
// (applyPeerReadModels' viewer-scoped online/typing overlay, and everything
// users.getFullUser needs that getUsers itself doesn't).
namespace shuzagram::users {

// One resolved entry: the domain user plus whether it must be projected as
// the caller's own identity (EncodeUser's is_self) -- true both for an
// explicit inputUserSelf AND for an ordinary inputUser naming the caller's
// own id, exactly like the Go source.
struct ResolvedUser {
    domain::User user;
    bool self = false;
};

// Mirrors onUsersGetUsers: an unauthenticated or still-password-pending
// auth_key resolves every input to nothing (never an error -- Go silently
// skips ids it can't serve to an unauthorized caller), and an unknown/
// access_hash-mismatched id is dropped rather than failing the whole call.
// Preserves the caller's input order.
std::vector<ResolvedUser> ResolveGetUsers(store::IAuthorizationStore& authorizations, store::IUserStore& users,
                                           const std::array<std::uint8_t, 8>& auth_key_id,
                                           const std::vector<mtproto::messages::InputUser>& inputs);

} // namespace shuzagram::users
