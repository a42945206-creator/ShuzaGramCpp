#include "shuzagram/account/update_status.hpp"

#include "shuzagram/auth/current_user.hpp"

namespace shuzagram::account {

void UpdateStatus(store::IAuthorizationStore& authorizations, store::IUserStore& users,
                   const std::array<std::uint8_t, 8>& auth_key_id, int now) {
    const auto current = auth::ResolveCurrentUser(authorizations, auth_key_id);
    if (!current.authorized || current.user_id == 0) return;
    users.UpdateLastSeen(current.user_id, now);
}

} // namespace shuzagram::account
