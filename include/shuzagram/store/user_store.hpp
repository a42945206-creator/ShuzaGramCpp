#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "shuzagram/domain/user.hpp"

// Port of the store.UserStore interface (internal/store, backed by
// internal/store/postgres/user.go). Only the operations needed by the
// login/identity chain are ported in this first slice; the remaining
// mutations in queries/user.sql (color, profile-color, personal channel,
// emoji status, birthday, scam/fake, search) follow once the profile-update
// RPC path is ported.
//
// Design note: Go's (User, bool, error) three-way return becomes
// std::optional<domain::User> for the ordinary not-found case, plus a thrown
// shuzagram::domain::Error (or subclass) for anything else -- ByPhone("")
// intentionally returning "not found" rather than throwing is preserved
// below.
namespace shuzagram::store {

class IUserStore {
public:
    virtual ~IUserStore() = default;

    virtual std::optional<domain::User> ByID(std::int64_t id) = 0;
    virtual std::vector<domain::User> ByIDs(const std::vector<std::int64_t>& ids) = 0;

    // phone == "" always returns std::nullopt: bot rows carry an empty
    // phone, and users.phone uniqueness only covers non-empty values, so an
    // empty query must never resolve to an arbitrary bot row.
    virtual std::optional<domain::User> ByPhone(const std::string& phone) = 0;

    // Editable-slot lookup only; the collectible-username registry fallback
    // (peer_usernames) is ported alongside the username-registry module.
    virtual std::optional<domain::User> ByUsername(const std::string& username) = 0;

    // Throws domain::UsernameOccupiedError if username (after normalization)
    // is already held by another peer or reserved as an unassigned
    // collectible asset.
    virtual domain::User Create(const domain::User& user) = 0;

    // Throws domain::UserNotFoundError if id does not name a live
    // (non-deleted) user.
    virtual domain::User SetPremiumUntil(std::int64_t user_id, int until) = 0;
    virtual domain::User SetVerified(std::int64_t user_id, bool verified) = 0;
    virtual domain::User SetSupport(std::int64_t user_id, bool support) = 0;
    virtual void UpdateLastSeen(std::int64_t user_id, int last_seen_at) = 0;
    virtual domain::User UpdateProfile(std::int64_t user_id, const std::string& first_name,
                                       const std::string& last_name, const std::string& about) = 0;
};

} // namespace shuzagram::store
