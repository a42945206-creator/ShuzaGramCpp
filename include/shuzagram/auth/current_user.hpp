#pragma once

#include <array>
#include <cstdint>

#include "shuzagram/store/authorization_store.hpp"

// Mirrors the authorization half of Router.currentUserID
// (internal/rpc/convert_auth.go) -- the per-connection session-bind cache
// there is not ported (this project has no session cache yet, so every
// call re-queries the store), only the authoritative rule every RPC handler
// in the real server relies on: an auth_key with no bound authorization, or
// one still password_pending (SMS-verified but 2FA not completed), resolves
// to "not authorized" -- never a partial identity and never an error.
namespace shuzagram::auth {

struct CurrentUser {
    std::int64_t user_id = 0;
    bool authorized = false;
};

CurrentUser ResolveCurrentUser(store::IAuthorizationStore& authorizations,
                                const std::array<std::uint8_t, 8>& auth_key_id);

} // namespace shuzagram::auth
