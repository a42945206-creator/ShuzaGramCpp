#include "shuzagram/store/postgres/user_store.hpp"

#include <sstream>

#include <nlohmann/json.hpp>

#include "shuzagram/domain/user_errors.hpp"

// Ported from internal/store/postgres/user.go against the schema
// introspected live from the running deployment (`\d users`, 2026-09-18).
// Only the operations declared in store::IUserStore are implemented; see
// that header for what's deferred to later slices.
namespace shuzagram::store::postgres {

namespace {

// Every read path (plain SELECT, or an UPDATE/INSERT ... RETURNING) is
// wrapped in this CTE so row_to_user() has exactly one column shape to
// understand, and so nullable timestamptz columns become plain optional
// Unix-second integers before they ever reach C++ -- pgx does this
// implicitly via its timestamptz decoder; libpqxx has no equivalent, so the
// conversion is pushed into SQL instead.
std::string WrapProjection(const std::string& cte_body) {
    return "WITH src AS (\n" + cte_body + "\n)\n" R"SQL(
SELECT
  id, access_hash, phone, first_name, last_name, about, username, country_code,
  verified, scam, fake, support, is_bot, bot_info_version,
  EXTRACT(EPOCH FROM premium_expires_at)::bigint AS premium_until,
  emoji_status_document_id, emoji_status_until,
  emoji_status_collectible_id, emoji_status_collectible::text AS emoji_status_collectible,
  birthday_day, birthday_month, birthday_year,
  personal_channel_id, linked_community_id,
  color_set, color, color_background_emoji_id,
  profile_color_set, profile_color, profile_color_background_emoji_id,
  last_seen_at,
  (deleted_at IS NOT NULL) AS is_deleted,
  EXTRACT(EPOCH FROM deleted_at)::bigint AS deleted_at_epoch,
  deletion_source, deletion_reason,
  EXTRACT(EPOCH FROM created_at) AS created_at_epoch,
  EXTRACT(EPOCH FROM account_delete_at) AS account_delete_at_epoch
FROM src
)SQL";
}

// Mirrors mustDecodeEmojiStatusCollectible in user.go: the users table's own
// check constraints (users_emoji_status_shape_check) already guarantee this
// shape, so a mismatch here means the C++ and SQL sides disagree about the
// invariant, not a bad row -- hence throwing rather than degrading silently.
domain::EmojiStatusCollectible DecodeEmojiStatusCollectible(std::optional<std::int64_t> id,
                                                             const std::string& raw_json) {
    const auto parsed = nlohmann::json::parse(raw_json, nullptr, /*allow_exceptions=*/false);
    domain::EmojiStatusCollectible collectible;
    if (!parsed.is_discarded() && parsed.is_object() && !parsed.empty()) {
        collectible.collectible_id = parsed.value("collectible_id", std::int64_t{0});
        collectible.document_id = parsed.value("document_id", std::int64_t{0});
        collectible.title = parsed.value("title", std::string{});
        collectible.slug = parsed.value("slug", std::string{});
        collectible.pattern_document_id = parsed.value("pattern_document_id", std::int64_t{0});
        collectible.center_color = parsed.value("center_color", 0);
        collectible.edge_color = parsed.value("edge_color", 0);
        collectible.pattern_color = parsed.value("pattern_color", 0);
        collectible.text_color = parsed.value("text_color", 0);
    }
    if (!id.has_value()) {
        if (!collectible.Empty()) {
            throw domain::Error("users emoji-status invariant: snapshot exists without collectible id");
        }
        return {};
    }
    if (!collectible.Valid() || collectible.collectible_id != *id) {
        throw domain::Error("users emoji-status invariant: incomplete or mismatched collectible snapshot");
    }
    return collectible;
}

domain::PeerColor PeerColorFromRow(bool has_color, int color, std::int64_t background_emoji_id) {
    return domain::PeerColor{has_color, color, background_emoji_id};
}

domain::User RowToUser(const pqxx::row& r) {
    const bool is_deleted = r["is_deleted"].as<bool>();

    domain::User u;
    u.id = r["id"].as<std::int64_t>();
    u.access_hash = r["access_hash"].as<std::int64_t>();
    u.phone = r["phone"].as<std::string>();
    u.first_name = r["first_name"].as<std::string>();
    u.last_name = r["last_name"].as<std::string>();
    u.about = r["about"].as<std::string>();
    u.username = r["username"].as<std::string>();
    u.country_code = r["country_code"].as<std::string>();
    u.verified = r["verified"].as<bool>();
    u.scam = r["scam"].as<bool>();
    u.fake = r["fake"].as<bool>();
    u.support = r["support"].as<bool>();
    u.bot = r["is_bot"].as<bool>();
    u.bot_info_version = r["bot_info_version"].as<int>();
    u.premium_until = static_cast<int>(r["premium_until"].as<std::int64_t>(0));
    u.emoji_status_document_id = r["emoji_status_document_id"].as<std::int64_t>();
    u.emoji_status_until = r["emoji_status_until"].as<int>();
    u.emoji_status_collectible = DecodeEmojiStatusCollectible(
        r["emoji_status_collectible_id"].get<std::int64_t>(),
        r["emoji_status_collectible"].as<std::string>());
    u.birthday = domain::Birthday{r["birthday_day"].as<int>(), r["birthday_month"].as<int>(),
                                   r["birthday_year"].as<int>()};
    u.personal_channel_id = r["personal_channel_id"].as<std::int64_t>();
    u.linked_community_id = r["linked_community_id"].as<std::int64_t>();
    u.color = PeerColorFromRow(r["color_set"].as<bool>(), r["color"].as<int>(),
                                r["color_background_emoji_id"].as<std::int64_t>());
    u.profile_color = PeerColorFromRow(r["profile_color_set"].as<bool>(), r["profile_color"].as<int>(),
                                        r["profile_color_background_emoji_id"].as<std::int64_t>());
    u.last_seen_at = r["last_seen_at"].as<int>();
    u.deleted = is_deleted;
    u.deletion_source = domain::AccountDeletionSourceFromString(r["deletion_source"].as<std::string>());
    u.deletion_reason = r["deletion_reason"].as<std::string>();
    u.created_at = std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::duration<double>(r["created_at_epoch"].as<double>()))};
    if (auto acc_del = r["account_delete_at_epoch"]; !acc_del.is_null()) {
        u.account_delete_at = std::chrono::system_clock::time_point{
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::duration<double>(acc_del.as<double>()))};
    }

    if (is_deleted) {
        u.deleted_at = r["deleted_at_epoch"].as<std::int64_t>(0);
        return u.DeletedTombstone();
    }
    return u;
}

std::string BigintArrayLiteral(const std::vector<std::int64_t>& ids) {
    std::ostringstream out;
    out << '{';
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (i) out << ',';
        out << ids[i];
    }
    out << '}';
    return out.str();
}

bool IsUniqueViolation(const pqxx::sql_error& e, std::string_view constraint) {
    // SQLSTATE 23505 = unique_violation. libpqxx doesn't parse out the
    // constraint name, so match it in the message the same way
    // isUniqueConstraint(err, name) does on the Go side.
    return std::string_view(e.sqlstate()) == "23505" &&
           std::string_view(e.what()).find(constraint) != std::string_view::npos;
}

struct PeerUsernameOwner {
    std::string peer_type;
    std::int64_t peer_id = 0;
    bool collectible = false;
    bool active = false;
    bool editable = false;
};

std::optional<PeerUsernameOwner> GetPeerUsernameOwner(pqxx::transaction_base& tx,
                                                       const std::string& username_lower, bool for_update) {
    if (username_lower.empty()) return std::nullopt;
    std::string query =
        "SELECT peer_type, peer_id, collectible_id IS NOT NULL, active, editable "
        "FROM peer_usernames WHERE username_lower = $1";
    if (for_update) query += " FOR UPDATE";
    const auto result = tx.exec(query, pqxx::params{username_lower});
    if (result.empty()) return std::nullopt;
    const auto& r = result[0];
    return PeerUsernameOwner{r[0].as<std::string>(), r[1].as<std::int64_t>(), r[2].as<bool>(), r[3].as<bool>(),
                              r[4].as<bool>()};
}

bool CollectibleUsernameReserved(pqxx::transaction_base& tx, const std::string& username_lower) {
    const auto result = tx.exec(
        "SELECT EXISTS (SELECT 1 FROM collectible_usernames WHERE username_lower = $1 AND status <> 'burned')",
        pqxx::params{username_lower});
    return result[0][0].as<bool>();
}

// Port of replacePeerUsernameTx (peer_username.go): rewrites the peer's
// editable username slot inside an already-open transaction. An empty pair
// clears the slot. Collectible rows are never touched.
void ReplacePeerUsernameTx(pqxx::transaction_base& tx, const std::string& peer_type, std::int64_t peer_id,
                            const std::string& username, const std::string& username_lower) {
    if (!username_lower.empty()) {
        const auto owner = GetPeerUsernameOwner(tx, username_lower, /*for_update=*/true);
        const bool matches = owner && owner->peer_type == peer_type && owner->peer_id == peer_id;
        if (owner && (!matches || owner->collectible)) {
            throw domain::UsernameOccupiedError();
        }
        if (!owner && CollectibleUsernameReserved(tx, username_lower)) {
            throw domain::UsernameOccupiedError();
        }
    }
    tx.exec("DELETE FROM peer_usernames WHERE peer_type = $1 AND peer_id = $2 AND editable",
            pqxx::params{peer_type, peer_id});
    if (username_lower.empty()) return;
    try {
        tx.exec(
            "INSERT INTO peer_usernames (username_lower, peer_type, peer_id, username, active, editable, "
            "sort_order, collectible_id) VALUES ($1, $2, $3, $4, true, true, 0, NULL)",
            pqxx::params{username_lower, peer_type, peer_id, username});
    } catch (const pqxx::unique_violation&) {
        throw domain::UsernameOccupiedError();
    }
}

std::string TrimUsername(std::string username) {
    // Mirrors strings.TrimSpace(strings.TrimPrefix(username, "@")).
    if (!username.empty() && username.front() == '@') username.erase(0, 1);
    const auto first = username.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) return "";
    const auto last = username.find_last_not_of(" \t\n\r\f\v");
    return username.substr(first, last - first + 1);
}

std::string ToLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Mirrors encodeEmojiStatusCollectible in user.go: validates the snapshot
// shape and, for a non-empty collectible, serializes it to the jsonb column
// value plus its id. Returns ("{}", nullopt) for the "clear" / plain-document
// case.
struct EncodedEmojiStatus {
    std::string json;
    std::optional<std::int64_t> collectible_id;
};

EncodedEmojiStatus EncodeEmojiStatusCollectible(const domain::UserEmojiStatus& status) {
    if (!status.Valid()) throw domain::StarGiftCollectibleInvalidError();
    if (status.collectible.Empty()) return {"{}", std::nullopt};
    nlohmann::json j;
    j["collectible_id"] = status.collectible.collectible_id;
    j["document_id"] = status.collectible.document_id;
    j["title"] = status.collectible.title;
    j["slug"] = status.collectible.slug;
    j["pattern_document_id"] = status.collectible.pattern_document_id;
    j["center_color"] = status.collectible.center_color;
    j["edge_color"] = status.collectible.edge_color;
    j["pattern_color"] = status.collectible.pattern_color;
    j["text_color"] = status.collectible.text_color;
    return {j.dump(), status.collectible.collectible_id};
}

} // namespace

std::optional<domain::User> UserStore::ByID(std::int64_t id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(WrapProjection("SELECT * FROM users WHERE id = $1"), pqxx::params{id});
    tx.commit();
    if (result.empty()) return std::nullopt;
    return RowToUser(result[0]);
}

std::vector<domain::User> UserStore::ByIDs(const std::vector<std::int64_t>& ids) {
    if (ids.empty()) return {};
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("SELECT * FROM users WHERE id = ANY($1::bigint[]) ORDER BY id"),
        pqxx::params{BigintArrayLiteral(ids)});
    tx.commit();
    std::vector<domain::User> out;
    out.reserve(result.size());
    for (const auto& row : result) out.push_back(RowToUser(row));
    return out;
}

std::optional<domain::User> UserStore::ByPhone(const std::string& phone) {
    // Bot rows carry phone = '' (uniqueness only covers non-empty values);
    // an empty query must never resolve to an arbitrary bot row.
    if (phone.empty()) return std::nullopt;
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("SELECT * FROM users WHERE phone = $1 AND deleted_at IS NULL"), pqxx::params{phone});
    tx.commit();
    if (result.empty()) return std::nullopt;
    return RowToUser(result[0]);
}

std::optional<domain::User> UserStore::ByUsername(const std::string& username_in) {
    const std::string username = TrimUsername(username_in);
    if (username.empty()) return std::nullopt;
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("SELECT * FROM users WHERE lower(username) = lower($1) AND username <> '' "
                        "AND deleted_at IS NULL"),
        pqxx::params{username});
    tx.commit();
    if (result.empty()) {
        // The collectible-username registry fallback (byCollectibleUsername
        // in user.go) is ported alongside the username-registry module.
        return std::nullopt;
    }
    return RowToUser(result[0]);
}

domain::User UserStore::Create(const domain::User& user_in) {
    domain::User user = user_in;
    user.username = TrimUsername(user.username);

    pqxx::work tx(db_.conn());
    pqxx::row row;
    try {
        const std::optional<std::int64_t> premium_epoch =
            user.premium_until > 0 ? std::optional<std::int64_t>(user.premium_until) : std::nullopt;
        row = tx.exec(WrapProjection(
                          "INSERT INTO users (access_hash, phone, first_name, last_name, username, "
                          "country_code, premium_expires_at) VALUES ($1, $2, $3, $4, $5, $6, "
                          "to_timestamp($7)) RETURNING *"),
                      pqxx::params{user.access_hash, user.phone, user.first_name, user.last_name,
                                   user.username, user.country_code, premium_epoch})[0];
    } catch (const pqxx::sql_error& e) {
        if (IsUniqueViolation(e, "users_username_lower_unique_idx")) throw domain::UsernameOccupiedError();
        throw;
    }

    const std::int64_t new_id = row["id"].as<std::int64_t>();
    const std::string username_lower = ToLower(row["username"].as<std::string>());
    if (!username_lower.empty()) {
        ReplacePeerUsernameTx(tx, "user", new_id, row["username"].as<std::string>(), username_lower);
    }
    tx.commit();
    return RowToUser(row);
}

domain::User UserStore::SetPremiumUntil(std::int64_t user_id, int until) {
    pqxx::work tx(db_.conn());
    const std::optional<std::int64_t> premium_epoch =
        until > 0 ? std::optional<std::int64_t>(until) : std::nullopt;
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET premium_expires_at = to_timestamp($2), updated_at = now() "
                        "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, premium_epoch});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::SetVerified(std::int64_t user_id, bool verified) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET verified = $2, updated_at = now() "
                        "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, verified});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::SetSupport(std::int64_t user_id, bool support) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET support = $2, updated_at = now() "
                        "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, support});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

void UserStore::UpdateLastSeen(std::int64_t user_id, int last_seen_at) {
    pqxx::work tx(db_.conn());
    tx.exec("UPDATE users SET last_seen_at = GREATEST(last_seen_at, $2), updated_at = now() "
            "WHERE id = $1 AND deleted_at IS NULL",
            pqxx::params{user_id, static_cast<std::int64_t>(last_seen_at)});
    tx.commit();
}

domain::User UserStore::UpdateProfile(std::int64_t user_id, const std::string& first_name,
                                       const std::string& last_name, const std::string& about) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET first_name = $2, last_name = $3, about = $4, updated_at = now() "
                        "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, first_name, last_name, about});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::UpdateUsername(std::int64_t user_id, const std::string& username_in) {
    const std::string username = TrimUsername(username_in);
    const std::string username_lower = ToLower(username);

    pqxx::work tx(db_.conn());
    {
        const auto locked =
            tx.exec("SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
                    pqxx::params{user_id});
        if (locked.empty()) throw domain::UsernameNotOccupiedError();
    }
    ReplacePeerUsernameTx(tx, "user", user_id, username, username_lower);

    pqxx::result result;
    try {
        result = tx.exec(
            WrapProjection("UPDATE users SET username = $2, updated_at = now() "
                            "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
            pqxx::params{user_id, username});
    } catch (const pqxx::sql_error& e) {
        if (IsUniqueViolation(e, "users_username_lower_unique_idx")) throw domain::UsernameOccupiedError();
        throw;
    }
    if (result.empty()) throw domain::UsernameNotOccupiedError();
    tx.commit();
    return RowToUser(result[0]);
}

domain::User UserStore::UpdatePhone(std::int64_t user_id, const std::string& phone) {
    pqxx::work tx(db_.conn());
    pqxx::result result;
    try {
        result = tx.exec(
            WrapProjection("UPDATE users SET phone = $2, updated_at = now() "
                            "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
            pqxx::params{user_id, phone});
    } catch (const pqxx::sql_error& e) {
        if (IsUniqueViolation(e, "users_phone_unique_idx")) throw domain::PhoneNumberOccupiedError();
        throw;
    }
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::SetScamFake(std::int64_t user_id, bool scam, bool fake) {
    if (scam && fake) throw domain::PeerModerationFlagsInvalidError();

    pqxx::work tx(db_.conn());
    const auto current = tx.exec("SELECT scam, fake FROM users WHERE id = $1 FOR UPDATE", pqxx::params{user_id});
    if (current.empty()) throw domain::UserNotFoundError();

    if (current[0][0].as<bool>() == scam && current[0][1].as<bool>() == fake) {
        const auto result = tx.exec(WrapProjection("SELECT * FROM users WHERE id = $1"), pqxx::params{user_id});
        tx.commit();
        return RowToUser(result[0]);
    }

    const auto result = tx.exec(
        WrapProjection("UPDATE users SET scam = $2, fake = $3, updated_at = now() "
                        "WHERE id = $1 RETURNING *"),
        pqxx::params{user_id, scam, fake});
    if (result.empty()) throw domain::UserNotFoundError();
    tx.commit();
    return RowToUser(result[0]);
}

std::vector<domain::User> UserStore::SweepExpiredPremium(std::int64_t now, int limit) {
    if (limit <= 0) return {};
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection(R"SQL(
UPDATE users
SET premium_expires_at = NULL, updated_at = now()
WHERE id IN (
  SELECT id FROM users
  WHERE premium_expires_at IS NOT NULL AND deleted_at IS NULL AND premium_expires_at <= to_timestamp($1)
  ORDER BY premium_expires_at
  LIMIT $2
)
RETURNING *
)SQL"),
        pqxx::params{now, limit});
    tx.commit();
    std::vector<domain::User> out;
    out.reserve(result.size());
    for (const auto& row : result) out.push_back(RowToUser(row));
    return out;
}

domain::User UserStore::UpdateEmojiStatus(std::int64_t user_id, const domain::UserEmojiStatus& status) {
    const EncodedEmojiStatus encoded = EncodeEmojiStatusCollectible(status);
    if (!status.collectible.Empty()) {
        // The Go source locks unique_star_gifts, re-derives the expected
        // snapshot from the owned gift, and rejects a mismatched/foreign/
        // burned one (updateEmojiStatusRow in user.go) before writing. That
        // whole check depends on the star-gift/unique_star_gifts module,
        // which isn't ported yet -- so this path refuses rather than writing
        // an unverified collectible snapshot.
        throw domain::NotImplementedError(
            "UpdateEmojiStatus with a collectible snapshot (needs the star-gift module)");
    }

    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection(
            "UPDATE users SET emoji_status_document_id = $2, emoji_status_until = $3, "
            "emoji_status_collectible_id = $4, emoji_status_collectible = $5::jsonb, updated_at = now() "
            "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, status.document_id, static_cast<std::int64_t>(status.until),
                     encoded.collectible_id, encoded.json});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::UpdateBirthday(std::int64_t user_id, const domain::Birthday& birthday) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET birthday_day = $2, birthday_month = $3, birthday_year = $4, "
                        "updated_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, birthday.day, birthday.month, birthday.year});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::UpdatePersonalChannel(std::int64_t user_id, std::int64_t channel_id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        WrapProjection("UPDATE users SET personal_channel_id = $2, updated_at = now() "
                        "WHERE id = $1 AND deleted_at IS NULL RETURNING *"),
        pqxx::params{user_id, channel_id});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

domain::User UserStore::UpdateColor(std::int64_t user_id, bool for_profile, const domain::PeerColor& color) {
    pqxx::work tx(db_.conn());
    const std::string column_prefix = for_profile ? "profile_color" : "color";
    const std::string sql = "UPDATE users SET " + column_prefix + "_set = $2, " + column_prefix +
                             " = $3, " + column_prefix +
                             "_background_emoji_id = $4, updated_at = now() "
                             "WHERE id = $1 AND deleted_at IS NULL RETURNING *";
    const auto result = tx.exec(WrapProjection(sql),
                                 pqxx::params{user_id, color.has_color, color.color, color.background_emoji_id});
    tx.commit();
    if (result.empty()) throw domain::UserNotFoundError();
    return RowToUser(result[0]);
}

} // namespace shuzagram::store::postgres
