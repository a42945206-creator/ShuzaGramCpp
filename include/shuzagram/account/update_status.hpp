#pragma once

#include <array>
#include <cstdint>

#include "shuzagram/store/authorization_store.hpp"
#include "shuzagram/store/user_store.hpp"

// Faithful, scoped port of onAccountUpdateStatus (internal/rpc/account.go)
// plus the durable half of setPresenceFromContext/persistLastSeen
// (internal/rpc/presence.go). See NOTES/account-update-status-plan.md for
// what's cut: the in-memory presence tracker, the updateUserStatus push to
// online contacts, and the online-refresh write debounce. None of that
// changes the durable end state this function produces (users.last_seen_at);
// it only changes real-time fan-out and write-amortization, both of which
// need session/update-delivery infrastructure this port doesn't have yet.
namespace shuzagram::account {

// Mirrors onAccountUpdateStatus: an unauthorized or still-password-pending
// caller is a silent no-op, never an error (the wire response is always
// boolTrue regardless -- see HandleAccountUpdateStatus). offline is decoded
// off the wire but doesn't yet change the persisted outcome: both branches
// of the real handler write last_seen_at = now, and the online/offline
// distinction only matters for the (not yet ported) live presence push.
void UpdateStatus(store::IAuthorizationStore& authorizations, store::IUserStore& users,
                   const std::array<std::uint8_t, 8>& auth_key_id, int now);

} // namespace shuzagram::account
