#include "shuzagram/auth/current_user.hpp"

namespace shuzagram::auth {

CurrentUser ResolveCurrentUser(store::IAuthorizationStore& authorizations,
                                const std::array<std::uint8_t, 8>& auth_key_id) {
    const auto authz = authorizations.ByAuthKey(auth_key_id);
    if (!authz.has_value() || authz->password_pending) return CurrentUser{};
    return CurrentUser{authz->user_id, true};
}

} // namespace shuzagram::auth
