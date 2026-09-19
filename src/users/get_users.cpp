#include "shuzagram/users/get_users.hpp"

#include <unordered_map>
#include <unordered_set>

namespace shuzagram::users {

std::vector<ResolvedUser> ResolveGetUsers(store::IAuthorizationStore& authorizations, store::IUserStore& users,
                                           const std::array<std::uint8_t, 8>& auth_key_id,
                                           const std::vector<mtproto::messages::InputUser>& inputs) {
    using mtproto::messages::InputUser;

    const auto authz = authorizations.ByAuthKey(auth_key_id);
    const bool authorized = authz.has_value() && !authz->password_pending;
    const std::int64_t current_user_id = authorized ? authz->user_id : 0;

    bool need_self = false;
    std::vector<InputUser> resolved_inputs;
    resolved_inputs.reserve(inputs.size());
    std::vector<std::int64_t> unique_ids;
    std::unordered_set<std::int64_t> seen_ids;

    for (const auto& in : inputs) {
        if (in.kind == InputUser::Kind::SelfUser) {
            if (!authorized) continue;
            need_self = true;
            resolved_inputs.push_back(in);
        } else if (in.kind == InputUser::Kind::ById) {
            if (!authorized || in.user_id == 0) continue;
            resolved_inputs.push_back(in);
            if (seen_ids.insert(in.user_id).second) {
                unique_ids.push_back(in.user_id);
            }
        }
        // Kind::Empty matches nothing in Go's switch either -- dropped.
    }

    std::optional<domain::User> self_user;
    if (need_self) {
        self_user = users.ByID(current_user_id);
        if (!self_user.has_value()) need_self = false;
    }

    std::unordered_map<std::int64_t, domain::User> users_by_id;
    if (!unique_ids.empty()) {
        for (auto& u : users.ByIDs(unique_ids)) {
            if (u.id != 0) users_by_id.emplace(u.id, std::move(u));
        }
    }

    std::vector<ResolvedUser> out;
    out.reserve(resolved_inputs.size());
    for (const auto& in : resolved_inputs) {
        if (in.kind == InputUser::Kind::SelfUser) {
            if (need_self) out.push_back(ResolvedUser{*self_user, true});
            continue;
        }
        const auto it = users_by_id.find(in.user_id);
        if (it == users_by_id.end()) continue;
        if (in.access_hash != 0 && in.access_hash != it->second.access_hash) continue;
        // A client may also request its own id via an ordinary inputUser
        // (not inputUserSelf); it must still be projected as self, or the
        // client's local Saved-Messages cache desyncs from its own account.
        const bool is_self = it->second.id == current_user_id;
        out.push_back(ResolvedUser{it->second, is_self});
    }
    return out;
}

} // namespace shuzagram::users
