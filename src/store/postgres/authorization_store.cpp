#include "shuzagram/store/postgres/authorization_store.hpp"

#include <sstream>

#include "auth_identity_lock.hpp"
#include "auth_key_codec.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/store/errors.hpp"

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

} // namespace

void AuthorizationStore::Bind(const domain::Authorization&) {
    // bindAuthorization (authorization.go) interleaves the auth_key<->user
    // write with user_update_watermarks/user_update_retention/update_states
    // to commit a durable updates.getDifference delivery baseline in the
    // same transaction. That subsystem isn't ported yet; writing the
    // authorization row without it would produce a row with no valid pts
    // baseline, which every subsequent update-delivery read assumes exists.
    throw domain::NotImplementedError(
        "AuthorizationStore::Bind (needs the update_states/watermark/retention delivery-baseline subsystem)");
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
