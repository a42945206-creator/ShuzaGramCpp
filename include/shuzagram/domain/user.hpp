#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "shuzagram/domain/account_deletion.hpp"
#include "shuzagram/domain/message_entity.hpp"

// Faithful port of internal/domain/user.go. Field names, comments and
// invariants mirror the Go source so the two stay diffable; only the
// language-forced shape differs (e.g. Go's zero value vs. explicit defaults).
namespace shuzagram::domain {

// UserIDSequenceBase is the starting value for ordinary user IDs: the Unix
// second timestamp of 2026-06-01 00:00:00 Asia/Shanghai. System accounts
// (777000 etc.) sit below this range; registered users increment from here.
inline constexpr std::int64_t kUserIDSequenceBase = 1780243200;

// PeerColor is a domain-only representation of Telegram peerColor.
// has_color preserves explicit color=0, which is distinct from "color unset".
struct PeerColor {
    bool has_color = false;
    int color = 0;
    std::int64_t background_emoji_id = 0;

    [[nodiscard]] bool Empty() const {
        return !has_color && background_emoji_id == 0;
    }

    friend bool operator==(const PeerColor&, const PeerColor&) = default;
};

// EmojiStatusCollectible is the immutable projection needed to render a
// collectible gift as an emoji status. The source of truth remains the owned
// UniqueStarGift; users store an immutable snapshot so every user
// projection, online update and offline difference observes the same shape
// without an RPC-layer lookup.
struct EmojiStatusCollectible {
    std::int64_t collectible_id = 0;
    std::int64_t document_id = 0;
    std::string title;
    std::string slug;
    std::int64_t pattern_document_id = 0;
    int center_color = 0;
    int edge_color = 0;
    int pattern_color = 0;
    int text_color = 0;

    friend bool operator==(const EmojiStatusCollectible&, const EmojiStatusCollectible&) = default;

    [[nodiscard]] bool Empty() const { return *this == EmojiStatusCollectible{}; }

    // Valid enforces the complete collectible status shape. Partial snapshots
    // are forbidden because clients would otherwise render a gradient without
    // its model/pattern or be unable to resolve the collectible link.
    [[nodiscard]] bool Valid() const {
        if (collectible_id <= 0 || document_id <= 0 || pattern_document_id <= 0 ||
            title.empty() || slug.empty()) {
            return false;
        }
        for (int c : {center_color, edge_color, pattern_color, text_color}) {
            if (c < 0 || c > 0xffffff) return false;
        }
        return true;
    }
};

// UserEmojiStatus is the protocol-neutral mutation value accepted by the user
// service/store boundary. Exactly one of a normal document or a complete
// collectible snapshot may be active; the zero value clears the status.
struct UserEmojiStatus {
    std::int64_t document_id = 0;
    int until = 0;
    EmojiStatusCollectible collectible;

    [[nodiscard]] bool Empty() const { return document_id == 0 && collectible.Empty(); }

    [[nodiscard]] bool Valid() const {
        if (until < 0) return false;
        if (Empty()) return until == 0;
        if (document_id <= 0) return false;
        if (collectible.Empty()) return true;
        return collectible.Valid() && document_id == collectible.document_id;
    }
};

struct UserRestrictionReason {
    std::string platform;
    std::string reason;
    std::string text;
};

inline std::vector<UserRestrictionReason> AccountFrozenRestrictionReasons() {
    return {UserRestrictionReason{"all", "frozen", "This account is frozen."}};
}

// UserStatusKind is a protocol-neutral account presence state.
enum class UserStatusKind {
    Unknown,
    Online,
    Offline,
    Recently,
    LastWeek,
    LastMonth,
    Empty,
};

// UserStatus describes the currently visible presence state for a user.
// expires and was_online are absolute Unix timestamps in seconds, matching
// Telegram's UserStatus semantics without leaking tg.* into domain.
struct UserStatus {
    UserStatusKind kind = UserStatusKind::Unknown;
    int expires = 0;
    int was_online = 0;
};

// ApproximateUserStatus returns Telegram's coarse privacy-preserving
// last-seen buckets. Exact online/offline timestamps must never be
// reattached after this projection.
inline UserStatus ApproximateUserStatus(int last_seen_at, int now) {
    if (last_seen_at <= 0 || now <= 0 || last_seen_at >= now) {
        return UserStatus{UserStatusKind::Recently, 0, 0};
    }
    const int age = now - last_seen_at;
    if (age <= 3 * 24 * 60 * 60) return UserStatus{UserStatusKind::Recently, 0, 0};
    if (age <= 7 * 24 * 60 * 60) return UserStatus{UserStatusKind::LastWeek, 0, 0};
    if (age <= 30 * 24 * 60 * 60) return UserStatus{UserStatusKind::LastMonth, 0, 0};
    return UserStatus{UserStatusKind::Empty, 0, 0};
}

// Birthday is a user's public birthday. day/month == 0 means unset; year ==
// 0 means only month/day were provided.
struct Birthday {
    int day = 0;
    int month = 0;
    int year = 0;

    [[nodiscard]] bool IsSet() const { return day != 0 && month != 0; }

    friend bool operator==(const Birthday&, const Birthday&) = default;
};

// ValidBirthday validates month/day (year optional). Clear a birthday by
// passing the zero value (IsSet() == false).
inline bool ValidBirthday(const Birthday& b) {
    if (b.month < 1 || b.month > 12 || b.day < 1 || b.day > 31) return false;
    if (b.year != 0 && (b.year < 1900 || b.year > 2100)) return false;
    return true;
}

// UserProfileUpdate describes the optional-field mutation for
// account.updateProfile.
struct UserProfileUpdate {
    std::string first_name;
    bool has_first_name = false;
    std::string last_name;
    bool has_last_name = false;
    std::string about;
    bool has_about = false;
};

// User is an account. Phase 1 keeps only the fields required by the login
// chain; access_hash is required by every InputUser check and must not be
// dropped.
struct User {
    std::int64_t id = 0;
    std::int64_t access_hash = 0;
    std::string phone;
    std::string first_name;
    std::string last_name;
    std::string about;
    std::string username;
    std::string country_code;
    bool verified = false;
    bool scam = false;
    bool fake = false;
    bool support = false;
    bool contact = false;
    bool mutual = false;
    bool close_friend = false;

    // restriction_reasons are transient, viewer-scoped unavailability
    // reasons. They are produced after loading the viewer-independent base
    // user and must never be persisted in users or the base-user cache.
    std::vector<UserRestrictionReason> restriction_reasons;

    // contact_note / contact_note_entities are transient viewer-scoped
    // contact projection fields. They must never be persisted into users or
    // a viewer-independent base-user cache.
    std::string contact_note;
    std::vector<MessageEntity> contact_note_entities;

    // bot marks a bot account; when set, bot_info_version must be >= 1
    // (TDesktop only recognizes the user TL as a bot by the presence of
    // bot_info_version, and it shares bit 14 with the bot flag).
    bool bot = false;
    int bot_info_version = 0;

    // premium_until is the Unix-second premium expiry; 0 means non-premium.
    // It is the sole authority for premium state -- the read path derives
    // PremiumActiveAt() directly, so expiry stops premium immediately
    // without waiting on a background sweeper (the sweeper only handles
    // cleanup and notification push).
    int premium_until = 0;

    // emoji_status_document_id / emoji_status_until describe the user's
    // custom emoji status (premium-only, account.updateEmojiStatus).
    // document_id == 0 means unset; until == 0 means permanent.
    // emoji_status_collectible, when non-empty, must have document_id equal
    // to the collectible's model document id.
    std::int64_t emoji_status_document_id = 0;
    int emoji_status_until = 0;
    EmojiStatusCollectible emoji_status_collectible;

    // birthday is the user's public birthday (account.updateBirthday). The
    // zero value means unset.
    Birthday birthday;

    // personal_channel_id is the "personal channel" shown on the profile
    // page (account.updatePersonalChannel); 0 means unset. Profile
    // projection resolves the channel object and latest post from it.
    std::int64_t personal_channel_id = 0;

    // linked_community_id is the single Community containing this bot.
    // Ordinary users must keep it zero; the community aggregate enforces
    // that invariant.
    std::int64_t linked_community_id = 0;

    PeerColor color;
    PeerColor profile_color;

    // Profile photo fields are filled by app-layer user projection.
    // photo_id == 0 means no avatar.
    std::int64_t photo_id = 0;
    int photo_dc_id = 0;
    std::vector<std::uint8_t> photo_stripped;
    bool photo_personal = false;
    bool photo_has_video = false;

    int last_seen_at = 0;
    UserStatus status;

    // deleted is the durable tombstone state. Deleted users remain
    // addressable by id so historical messages can render "Deleted
    // Account", but all profile and reusable identity fields are cleared at
    // the store boundary.
    bool deleted = false;
    std::int64_t deleted_at = 0;
    AccountDeletionSource deletion_source = AccountDeletionSource::None;
    std::string deletion_reason;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point account_delete_at;

    // frozen_for_viewer is a transient, viewer-scoped marker: the account is
    // served to this viewer as a deleted tombstone because it is frozen, not
    // because it was deleted. It must never be persisted into users or a
    // viewer-independent base-user cache; the RPC boundary uses it to attach
    // the synthetic "frozen" third-party mark alongside the deleted
    // presentation.
    bool frozen_for_viewer = false;

    // PremiumActiveAt reports whether the user is a valid premium member at
    // `now` (Unix seconds). Bots are never premium (official semantics; the
    // grant path already excludes bots, this is belt-and-suspenders).
    [[nodiscard]] bool PremiumActiveAt(std::int64_t now) const {
        return !bot && premium_until > 0 && static_cast<std::int64_t>(premium_until) > now;
    }

    // EmojiStatusActiveAt reports whether the user has an active emoji
    // status at `now` (Unix seconds): set and not expired (until == 0 means
    // permanent). Emoji status is premium-only; once premium lapses it stops
    // being served even if the column still holds a stale value.
    [[nodiscard]] bool EmojiStatusActiveAt(std::int64_t now) const {
        const UserEmojiStatus status_snapshot = EmojiStatus();
        if (!PremiumActiveAt(now) || !status_snapshot.Valid() || emoji_status_document_id == 0) {
            return false;
        }
        return emoji_status_until == 0 || static_cast<std::int64_t>(emoji_status_until) > now;
    }

    // EmojiStatus returns the complete status snapshot carried by this user.
    [[nodiscard]] UserEmojiStatus EmojiStatus() const {
        return UserEmojiStatus{emoji_status_document_id, emoji_status_until, emoji_status_collectible};
    }

    // DeletedTombstone strips every viewer-dependent or personally
    // identifying field while preserving the immutable id and lifecycle
    // audit facts.
    [[nodiscard]] User DeletedTombstone() const {
        if (!deleted) return *this;
        User tombstone;
        tombstone.id = id;
        tombstone.access_hash = access_hash;
        tombstone.deleted = true;
        tombstone.deleted_at = deleted_at;
        tombstone.deletion_source = deletion_source;
        tombstone.deletion_reason = deletion_reason;
        tombstone.created_at = created_at;
        tombstone.account_delete_at = account_delete_at;
        tombstone.status = UserStatus{UserStatusKind::Empty, 0, 0};
        return tombstone;
    }
};

} // namespace shuzagram::domain
