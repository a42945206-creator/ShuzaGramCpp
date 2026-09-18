#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "shuzagram/domain/user.hpp"

// Port of the store.UserStore interface (internal/store, backed by
// internal/store/postgres/user.go). Every mutation in queries/user.sql is
// now covered except UpdateUserUsername's official-777000-claim variant
// (ClaimOfficialUsername, a startup-only reconciliation, not an ordinary
// mutation) and SearchUsers (needs the contacts/peer_usernames join surface
// ported first). UpdateEmojiStatus's collectible path throws
// domain::NotImplementedError until the star-gift/unique_star_gifts module
// is ported -- see its declaration below.
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

    // Throws domain::UsernameOccupiedError if the normalized username is
    // already held elsewhere, or domain::UsernameNotOccupiedError if user_id
    // does not name a live user.
    virtual domain::User UpdateUsername(std::int64_t user_id, const std::string& username) = 0;

    // Throws domain::PhoneNumberOccupiedError if phone is already the login
    // identity of another account, or domain::UserNotFoundError.
    virtual domain::User UpdatePhone(std::int64_t user_id, const std::string& phone) = 0;

    // Throws domain::PeerModerationFlagsInvalidError if both scam and fake
    // are set, or domain::UserNotFoundError.
    virtual domain::User SetScamFake(std::int64_t user_id, bool scam, bool fake) = 0;

    // Clears every premium row whose premium_expires_at is <= now (Unix
    // seconds), up to limit rows, returning the cleared users.
    virtual std::vector<domain::User> SweepExpiredPremium(std::int64_t now, int limit) = 0;

    // Atomically replaces the emoji-status snapshot. A non-empty
    // status.collectible throws domain::NotImplementedError: the Go source
    // locks and validates the owning unique_star_gifts row first, and that
    // module isn't ported yet. Throws domain::UserNotFoundError, or
    // domain::StarGiftCollectibleInvalidError if status isn't a valid
    // snapshot.
    virtual domain::User UpdateEmojiStatus(std::int64_t user_id, const domain::UserEmojiStatus& status) = 0;

    // The zero Birthday clears it. Throws domain::UserNotFoundError.
    virtual domain::User UpdateBirthday(std::int64_t user_id, const domain::Birthday& birthday) = 0;

    // channel_id == 0 clears the personal channel. Throws
    // domain::UserNotFoundError.
    virtual domain::User UpdatePersonalChannel(std::int64_t user_id, std::int64_t channel_id) = 0;

    // for_profile selects profile_color vs. color. Throws
    // domain::UserNotFoundError.
    virtual domain::User UpdateColor(std::int64_t user_id, bool for_profile, const domain::PeerColor& color) = 0;
};

} // namespace shuzagram::store
