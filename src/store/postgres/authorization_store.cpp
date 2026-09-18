#include "shuzagram/store/postgres/authorization_store.hpp"

#include <cstring>
#include <sstream>

#include <openssl/evp.h>

#include "auth_identity_lock.hpp"
#include "auth_key_codec.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/store/errors.hpp"
#include "user_lock.hpp"

// Ported from internal/store/postgres/authorization.go.
namespace shuzagram::store::postgres {

namespace {

using detail::AuthKeyIDFromInt64;
using detail::AuthKeyIDToInt64;

constexpr const char* kAuthorizationColumns =
    "auth_key_id, user_id, hash, layer, device_model, platform, system_version, api_id, app_version, ip, "
    "password_pending, EXTRACT(EPOCH FROM created_at) AS created_at_epoch, "
    "EXTRACT(EPOCH FROM active_at) AS active_at_epoch";

std::chrono::system_clock::time_point EpochToTimePoint(double seconds) {
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::duration<double>(seconds))};
}

domain::Authorization RowToAuthorization(const pqxx::row& r) {
    domain::Authorization a;
    a.auth_key_id = AuthKeyIDFromInt64(r["auth_key_id"].as<std::int64_t>());
    a.user_id = r["user_id"].as<std::int64_t>();
    a.hash = r["hash"].as<std::int64_t>();
    a.layer = r["layer"].as<int>();
    a.device_model = r["device_model"].as<std::string>();
    a.platform = r["platform"].as<std::string>();
    a.system_version = r["system_version"].as<std::string>();
    a.api_id = r["api_id"].as<int>();
    a.app_version = r["app_version"].as<std::string>();
    a.ip = r["ip"].as<std::string>();
    a.password_pending = r["password_pending"].as<bool>();
    a.created_at = EpochToTimePoint(r["created_at_epoch"].as<double>());
    a.active_at = EpochToTimePoint(r["active_at_epoch"].as<double>());
    return a;
}

// Port of authorizationHash (authorization.go:589): SHA-256 of the raw
// auth_key_id bytes, low 64 bits reinterpreted little-endian, with the
// (astronomically unlikely) zero result mapped to 1 so hash always
// distinguishes "unset" from a real value in the (user_id, hash) unique
// index.
std::int64_t AuthorizationHash(const std::array<std::uint8_t, 8>& auth_key_id) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    EVP_Digest(auth_key_id.data(), auth_key_id.size(), digest.data(), &digest_len, EVP_sha256(), nullptr);
    std::uint64_t low8;
    std::memcpy(&low8, digest.data(), 8);
    const auto hash = static_cast<std::int64_t>(low8);
    return hash == 0 ? 1 : hash;
}

} // namespace

// Port of bindAuthorization (authorization.go:51). Commits the auth_key <->
// user write and the device's update-delivery baseline as one state
// boundary. Lock order is fixed: target user advisory lock -> auth_keys
// parent row -> user_update_watermarks -> user_update_retention -> target
// update_states, matching the pruner's own lock order so a new
// authorization's observed baseline and the retained floor never commit
// across each other into a silent gap. The parent-row lock also serializes
// concurrent logins/re-logins of the same raw auth key even before its
// first authorization exists.
void AuthorizationStore::Bind(const domain::Authorization& a_in) {
    domain::Authorization a = a_in;
    if (a.hash == 0) a.hash = AuthorizationHash(a.auth_key_id);
    const std::int64_t key_id = AuthKeyIDToInt64(a.auth_key_id);

    detail::WithAuthIdentityTx(db_.conn(), "bind authorization", [&](pqxx::transaction_base& tx) {
        detail::LockUserForUpdate(tx, a.user_id);
        const auto user_row =
            tx.exec("SELECT deleted_at IS NULL FROM users WHERE id = $1 FOR UPDATE", pqxx::params{a.user_id});
        if (user_row.empty()) throw domain::UserNotFoundError();
        if (!user_row[0][0].as<bool>()) throw domain::AccountDeletedError();

        detail::LockPermanentAuthIdentities(tx, {key_id});
        const auto key_row = tx.exec("SELECT expires_at, layer, layer_observation_id FROM auth_keys "
                                      "WHERE auth_key_id = $1 FOR UPDATE",
                                      pqxx::params{key_id});
        if (key_row.empty()) throw AuthKeyNotFoundError();
        const int expires_at = key_row[0][0].as<int>();
        const int auth_layer = key_row[0][1].as<int>();
        const std::int64_t layer_observation_id = key_row[0][2].as<std::int64_t>();
        if (expires_at != 0) throw AuthKeyNotPermanentError();
        if (auth_layer < 0 || layer_observation_id < 0 || (layer_observation_id > 0 && auth_layer == 0)) {
            throw store::Error("authorization auth-key layer invariant violation: auth key has layer " +
                                std::to_string(auth_layer) + " observation " + std::to_string(layer_observation_id));
        }

        tx.exec("INSERT INTO user_update_watermarks (user_id, contiguous_pts) VALUES ($1, 0) "
                "ON CONFLICT (user_id) DO NOTHING",
                pqxx::params{a.user_id});
        const auto watermark_row = tx.exec(
            "SELECT contiguous_pts FROM user_update_watermarks WHERE user_id = $1 FOR UPDATE", pqxx::params{a.user_id});
        const int current_pts = watermark_row[0][0].as<int>();

        tx.exec("INSERT INTO user_update_retention (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
                pqxx::params{a.user_id});
        const auto retention_row = tx.exec(
            "SELECT retained_through_pts FROM user_update_retention WHERE user_id = $1 FOR UPDATE",
            pqxx::params{a.user_id});
        const int retained_floor = retention_row[0][0].as<int>();
        if (retained_floor > current_pts) {
            throw store::Error(
                "authorization update baseline invariant violation: user " + std::to_string(a.user_id) +
                " retained floor " + std::to_string(retained_floor) + " exceeds contiguous watermark " +
                std::to_string(current_pts));
        }

        // Every Bind is an explicit login baseline: delivered pts advances to
        // the account's already-locked contiguous watermark; observed only
        // advances to the already-deleted retained floor, never disguising a
        // live tail as client-confirmed. A stale historical state beyond the
        // account's contiguous watermark must fail fast, never GREATEST'd
        // into keeping an illegal future cursor. The WHERE also closes the
        // "concurrent insert after precheck" race.
        const auto upsert = tx.exec(
            "INSERT INTO update_states (auth_key_id, user_id, pts, qts, date, seq, observed_pts) "
            "VALUES ($1, $2, $3, 0, EXTRACT(EPOCH FROM now())::int, 0, $4) "
            "ON CONFLICT (auth_key_id, user_id) DO UPDATE SET "
            "pts = GREATEST(update_states.pts, EXCLUDED.pts), "
            "qts = GREATEST(update_states.qts, EXCLUDED.qts), "
            "date = GREATEST(update_states.date, EXCLUDED.date), "
            "seq = GREATEST(update_states.seq, EXCLUDED.seq), "
            "observed_pts = GREATEST(update_states.observed_pts, EXCLUDED.observed_pts), "
            "updated_at = now() "
            "WHERE update_states.pts >= 0 AND update_states.pts <= $3 AND update_states.observed_pts <= $3",
            pqxx::params{key_id, a.user_id, current_pts, retained_floor});
        if (upsert.affected_rows() != 1) {
            throw store::Error(
                "authorization update baseline invariant violation: auth key user " + std::to_string(a.user_id) +
                " has pts or observed_pts outside contiguous watermark " + std::to_string(current_pts));
        }

        tx.exec("DELETE FROM update_states WHERE auth_key_id = $1 AND user_id <> $2",
                pqxx::params{key_id, a.user_id});

        tx.exec(
            "INSERT INTO authorizations (auth_key_id, user_id, hash, layer, device_model, platform, "
            "system_version, api_id, app_version, ip, password_pending) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) "
            "ON CONFLICT (auth_key_id) DO UPDATE SET "
            "user_id = EXCLUDED.user_id, hash = EXCLUDED.hash, layer = EXCLUDED.layer, "
            "device_model = EXCLUDED.device_model, platform = EXCLUDED.platform, "
            "system_version = EXCLUDED.system_version, api_id = EXCLUDED.api_id, "
            "app_version = EXCLUDED.app_version, ip = EXCLUDED.ip, "
            "password_pending = EXCLUDED.password_pending, created_at = now(), active_at = now()",
            pqxx::params{key_id, a.user_id, a.hash, auth_layer, a.device_model, a.platform, a.system_version,
                         a.api_id, a.app_version, a.ip, a.password_pending});
    });
}

std::optional<domain::Authorization> AuthorizationStore::ByAuthKey(const std::array<std::uint8_t, 8>& auth_key_id) {
    pqxx::work tx(db_.conn());
    const auto result =
        tx.exec(std::string("SELECT ") + kAuthorizationColumns + " FROM authorizations WHERE auth_key_id = $1",
                pqxx::params{AuthKeyIDToInt64(auth_key_id)});
    tx.commit();
    if (result.empty()) return std::nullopt;
    return RowToAuthorization(result[0]);
}

void AuthorizationStore::UpdateClientInfo(const std::array<std::uint8_t, 8>& auth_key_id,
                                           const domain::AuthKeyClientInfo& info) {
    pqxx::work tx(db_.conn());
    tx.exec("UPDATE authorizations SET "
            "layer = CASE WHEN $2 > 0 THEN $2 ELSE layer END, "
            "device_model = CASE WHEN $3 <> '' THEN $3 ELSE device_model END, "
            "platform = CASE WHEN $4 <> '' THEN $4 ELSE platform END, "
            "system_version = CASE WHEN $5 <> '' THEN $5 ELSE system_version END, "
            "api_id = CASE WHEN $6 <> 0 THEN $6 ELSE api_id END, "
            "app_version = CASE WHEN $7 <> '' THEN $7 ELSE app_version END, "
            "ip = CASE WHEN $8 <> '' THEN $8 ELSE ip END, "
            "active_at = now() "
            "WHERE auth_key_id = $1",
            pqxx::params{AuthKeyIDToInt64(auth_key_id), info.layer, info.device_model, info.platform,
                         info.system_version, info.api_id, info.app_version, info.ip});
    tx.commit();
}

std::vector<domain::Authorization> AuthorizationStore::ListByUser(std::int64_t user_id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(std::string("SELECT ") + kAuthorizationColumns +
                                     " FROM authorizations WHERE user_id = $1 ORDER BY active_at DESC, auth_key_id DESC",
                                 pqxx::params{user_id});
    tx.commit();
    std::vector<domain::Authorization> out;
    out.reserve(result.size());
    for (const auto& row : result) out.push_back(RowToAuthorization(row));
    return out;
}

void AuthorizationStore::Delete(const std::array<std::uint8_t, 8>& auth_key_id) {
    pqxx::work tx(db_.conn());
    tx.exec("DELETE FROM authorizations WHERE auth_key_id = $1", pqxx::params{AuthKeyIDToInt64(auth_key_id)});
    tx.commit();
}

std::optional<domain::Authorization> AuthorizationStore::DeleteByHash(std::int64_t user_id, std::int64_t hash) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(std::string("DELETE FROM authorizations WHERE user_id = $1 AND hash = $2 "
                                             "RETURNING ") +
                                     kAuthorizationColumns,
                                 pqxx::params{user_id, hash});
    tx.commit();
    if (result.empty()) return std::nullopt;
    return RowToAuthorization(result[0]);
}

std::vector<domain::Authorization> AuthorizationStore::DeleteByUserExcept(
    std::int64_t user_id, const std::array<std::uint8_t, 8>& keep_auth_key_id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(std::string("DELETE FROM authorizations WHERE user_id = $1 AND auth_key_id <> $2 "
                                             "RETURNING ") +
                                     kAuthorizationColumns,
                                 pqxx::params{user_id, AuthKeyIDToInt64(keep_auth_key_id)});
    tx.commit();
    std::vector<domain::Authorization> out;
    out.reserve(result.size());
    for (const auto& row : result) out.push_back(RowToAuthorization(row));
    return out;
}

void AuthorizationStore::MarkPasswordPassed(const std::array<std::uint8_t, 8>& auth_key_id,
                                             std::int64_t expected_user_id) {
    pqxx::work tx(db_.conn());
    const auto tag =
        tx.exec("UPDATE authorizations SET password_pending = false, created_at = now(), active_at = now() "
                "WHERE auth_key_id = $1 AND user_id = $2 AND password_pending",
                pqxx::params{AuthKeyIDToInt64(auth_key_id), expected_user_id});
    if (tag.affected_rows() != 1) throw AuthorizationStateChangedError();
    tx.commit();
}

// revokeByHashTx/revokeByUserExceptTx (authorization.go) deliberately use
// separate READ COMMITTED statements. The first lookup is only a candidate:
// Bind locks auth_keys before changing authorization ownership, so
// revocation must lock the same parent row(s) and then re-read the
// owner/hash from a fresh statement snapshot -- otherwise an A->B re-login
// that commits while revoke waits could delete using A's stale target.

std::optional<domain::Authorization> AuthorizationStore::RevokeByHash(std::int64_t user_id, std::int64_t hash) {
    std::optional<domain::Authorization> result;
    detail::WithAuthIdentityTx(db_.conn(), "revoke authorization by hash", [&](pqxx::transaction_base& tx) {
        result.reset();
        const auto candidate_row =
            tx.exec("SELECT auth_key_id FROM authorizations WHERE user_id = $1 AND hash = $2",
                    pqxx::params{user_id, hash});
        if (candidate_row.empty()) return;
        const std::int64_t candidate = candidate_row[0][0].as<std::int64_t>();

        detail::LockPermanentAuthIdentities(tx, {candidate});
        const auto locked =
            tx.exec("SELECT auth_key_id FROM auth_keys WHERE auth_key_id = $1 FOR UPDATE", pqxx::params{candidate});
        if (locked.empty()) return;

        const auto revalidated = tx.exec(std::string("SELECT ") + kAuthorizationColumns +
                                              " FROM authorizations WHERE auth_key_id = $1 AND user_id = $2 "
                                              "AND hash = $3 FOR UPDATE",
                                          pqxx::params{candidate, user_id, hash});
        if (revalidated.empty()) return;
        const domain::Authorization a = RowToAuthorization(revalidated[0]);

        tx.exec("DELETE FROM update_states WHERE auth_key_id = $1", pqxx::params{candidate});
        const auto deleted =
            tx.exec("DELETE FROM authorizations WHERE auth_key_id = $1", pqxx::params{candidate});
        if (deleted.affected_rows() != 1) {
            throw store::Error("revoke authorization by hash: deleted " + std::to_string(deleted.affected_rows()) +
                                " of 1 locked target");
        }
        result = a;
    });
    return result;
}

std::vector<domain::Authorization> AuthorizationStore::RevokeByUserExcept(
    std::int64_t user_id, const std::array<std::uint8_t, 8>& keep_auth_key_id) {
    const std::int64_t keep_id = AuthKeyIDToInt64(keep_auth_key_id);
    std::vector<domain::Authorization> out;
    detail::WithAuthIdentityTx(db_.conn(), "revoke authorizations by user", [&](pqxx::transaction_base& tx) {
        out.clear();
        const auto candidate_rows =
            tx.exec("SELECT auth_key_id FROM authorizations WHERE user_id = $1 AND auth_key_id <> $2 "
                    "ORDER BY auth_key_id",
                    pqxx::params{user_id, keep_id});
        if (candidate_rows.empty()) return;
        std::vector<std::int64_t> candidates;
        candidates.reserve(candidate_rows.size());
        for (const auto& row : candidate_rows) candidates.push_back(row[0].as<std::int64_t>());

        detail::LockPermanentAuthIdentities(tx, candidates);

        // Advisory keys are already all held in final int32-hash order.
        // Parent rows are then locked by their real bigint IDs for
        // deterministic batch behavior.
        std::ostringstream ids_literal;
        ids_literal << '{';
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            if (i) ids_literal << ',';
            ids_literal << candidates[i];
        }
        ids_literal << '}';
        tx.exec("SELECT auth_key_id FROM auth_keys WHERE auth_key_id = ANY($1::bigint[]) ORDER BY auth_key_id "
                "FOR UPDATE",
                pqxx::params{ids_literal.str()});

        // A new statement snapshot after every parent lock: keys that
        // changed owner while waiting are omitted and stay intact.
        const auto revalidated =
            tx.exec(std::string("SELECT ") + kAuthorizationColumns +
                        " FROM authorizations WHERE user_id = $1 AND auth_key_id <> $2 "
                        "AND auth_key_id = ANY($3::bigint[]) ORDER BY created_at_epoch, auth_key_id FOR UPDATE",
                    pqxx::params{user_id, keep_id, ids_literal.str()});
        for (const auto& row : revalidated) out.push_back(RowToAuthorization(row));
        if (out.empty()) return;

        std::ostringstream targets_literal;
        targets_literal << '{';
        for (std::size_t i = 0; i < out.size(); ++i) {
            if (i) targets_literal << ',';
            targets_literal << AuthKeyIDToInt64(out[i].auth_key_id);
        }
        targets_literal << '}';
        tx.exec("DELETE FROM update_states WHERE auth_key_id = ANY($1::bigint[])",
                pqxx::params{targets_literal.str()});
        const auto deleted = tx.exec("DELETE FROM authorizations WHERE auth_key_id = ANY($1::bigint[])",
                                      pqxx::params{targets_literal.str()});
        if (deleted.affected_rows() != static_cast<pqxx::result::size_type>(out.size())) {
            throw store::Error("revoke authorizations by user: deleted " +
                                std::to_string(deleted.affected_rows()) + " of " + std::to_string(out.size()) +
                                " locked targets");
        }
    });
    return out;
}

} // namespace shuzagram::store::postgres
