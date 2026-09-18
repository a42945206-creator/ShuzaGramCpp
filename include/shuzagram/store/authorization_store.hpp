#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "shuzagram/domain/authorization.hpp"

// Port of the store.AuthorizationStore interface (internal/store/authorization.go).
namespace shuzagram::store {

class IAuthorizationStore {
public:
    virtual ~IAuthorizationStore() = default;

    // Commits the auth_key -> user binding and the device's update-delivery
    // baseline as one state boundary. Throws domain::NotImplementedError in
    // this slice: the Go source (bindAuthorization) interleaves this with
    // user_update_watermarks/user_update_retention/update_states, the
    // durable delivery-baseline subsystem, which isn't ported yet. Faking a
    // shortcut here would silently corrupt future updates.getDifference
    // baselines, so it refuses instead.
    virtual void Bind(const domain::Authorization& a) = 0;

    virtual std::optional<domain::Authorization> ByAuthKey(const std::array<std::uint8_t, 8>& auth_key_id) = 0;

    // Merge-updates a bound authorization's client metadata so the device
    // list stays consistent with the auth_key's own negotiation facts.
    virtual void UpdateClientInfo(const std::array<std::uint8_t, 8>& auth_key_id,
                                   const domain::AuthKeyClientInfo& info) = 0;

    virtual std::vector<domain::Authorization> ListByUser(std::int64_t user_id) = 0;

    virtual void Delete(const std::array<std::uint8_t, 8>& auth_key_id) = 0;

    virtual std::optional<domain::Authorization> DeleteByHash(std::int64_t user_id, std::int64_t hash) = 0;

    virtual std::vector<domain::Authorization> DeleteByUserExcept(std::int64_t user_id,
                                                                   const std::array<std::uint8_t, 8>& keep_auth_key_id) = 0;

    // Promotes only the pending identity whose password was just verified.
    // Throws AuthorizationStateChangedError if auth_key_id isn't currently
    // password_pending for expected_user_id (a concurrent cross-user Bind
    // must not let one proof clear another user's pending flag).
    virtual void MarkPasswordPassed(const std::array<std::uint8_t, 8>& auth_key_id, std::int64_t expected_user_id) = 0;
};

} // namespace shuzagram::store
