#include "shuzagram/store/postgres/auth_key_store.hpp"

#include <cstring>

#include "auth_identity_lock.hpp"
#include "auth_key_codec.hpp"

// Ported from internal/store/postgres/authkey.go. Only Save/Get/
// UpdateClientInfo/Delete are implemented -- see the interface header for
// what's deferred.
namespace shuzagram::store::postgres {

namespace {

using detail::AuthKeyIDFromInt64;
using detail::AuthKeyIDToInt64;

AuthKeyData RowToAuthKeyData(const pqxx::row& r) {
    AuthKeyData data;
    data.id = AuthKeyIDFromInt64(r["auth_key_id"].as<std::int64_t>());
    const auto body = r["body"].as<pqxx::bytes>();
    if (body.size() != data.value.size()) {
        throw store::Error("auth key body length = " + std::to_string(body.size()) + ", want " +
                            std::to_string(data.value.size()));
    }
    std::memcpy(data.value.data(), body.data(), body.size());
    data.server_salt = r["server_salt"].as<std::int64_t>();
    data.expires_at = r["expires_at"].as<int>();
    data.layer = r["layer"].as<int>();
    data.layer_observation_id = r["layer_observation_id"].as<std::int64_t>();
    data.device_model = r["device_model"].as<std::string>();
    data.platform = r["platform"].as<std::string>();
    data.system_version = r["system_version"].as<std::string>();
    data.api_id = r["api_id"].as<int>();
    data.app_version = r["app_version"].as<std::string>();
    if (const auto created_at = r["created_at_epoch"]; !created_at.is_null()) {
        data.created_at = created_at.as<std::int64_t>();
    }
    return data;
}

constexpr const char* kAuthKeyProjectionColumns =
    "auth_key_id, body, server_salt, EXTRACT(EPOCH FROM created_at)::bigint AS created_at_epoch, "
    "expires_at, layer, layer_observation_id, device_model, platform, system_version, api_id, app_version";

} // namespace

void AuthKeyStore::Save(const AuthKeyData& key) {
    if (!ValidNewAuthKeyProtocolExpiry(key.expires_at)) throw InvalidAuthKeyProtocolExpiryError();
    pqxx::work tx(db_.conn());
    const auto tag = tx.exec(
        "INSERT INTO auth_keys (auth_key_id, body, server_salt, expires_at) VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (auth_key_id) DO UPDATE SET server_salt = EXCLUDED.server_salt, last_used_at = now() "
        "WHERE auth_keys.body = EXCLUDED.body AND auth_keys.expires_at = EXCLUDED.expires_at",
        pqxx::params{AuthKeyIDToInt64(key.id), pqxx::binary_cast(key.value), key.server_salt, key.expires_at});
    if (tag.affected_rows() != 1) throw AuthKeyProtocolMetadataConflictError();
    tx.commit();
}

// Read and the last_used_at touch are the same UPDATE ... RETURNING: if
// orphan GC has already locked and deleted this row, Get waits and then sees
// no rows; if Get finishes first, GC's cutoff/final predicate sees the new
// watermark and skips it. This closes the window where a connection would
// read a stale key without yet being registered in the session manager.
std::optional<AuthKeyData> AuthKeyStore::Get(const std::array<std::uint8_t, 8>& id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(std::string("UPDATE auth_keys SET last_used_at = now() WHERE auth_key_id = $1 "
                                             "RETURNING ") +
                                     kAuthKeyProjectionColumns,
                                 pqxx::params{AuthKeyIDToInt64(id)});
    tx.commit();
    if (result.empty()) return std::nullopt;
    return RowToAuthKeyData(result[0]);
}

void AuthKeyStore::UpdateClientInfo(const std::array<std::uint8_t, 8>& id, const AuthKeyClientInfo& info) {
    const std::int64_t key_id = AuthKeyIDToInt64(id);
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        "UPDATE auth_keys SET "
        "layer = CASE WHEN $2::integer > 0 THEN $2 ELSE layer END, "
        "device_model = CASE WHEN $3::text <> '' THEN $3 ELSE device_model END, "
        "platform = CASE WHEN $4::text <> '' THEN $4 ELSE platform END, "
        "system_version = CASE WHEN $5::text <> '' THEN $5 ELSE system_version END, "
        "api_id = CASE WHEN $6::integer <> 0 THEN $6 ELSE api_id END, "
        "app_version = CASE WHEN $7::text <> '' THEN $7 ELSE app_version END "
        "WHERE auth_key_id = $1 AND ($2::integer <= 0 OR layer_observation_id = 0 OR layer = $2::integer) "
        "RETURNING 1",
        pqxx::params{key_id, info.layer, info.device_model, info.platform, info.system_version, info.api_id,
                     info.app_version});
    if (!result.empty()) {
        tx.commit();
        return;
    }
    const auto current =
        tx.exec("SELECT layer, layer_observation_id FROM auth_keys WHERE auth_key_id = $1", pqxx::params{key_id});
    tx.commit();
    if (current.empty()) throw AuthKeyNotFoundError();
    const int current_layer = current[0][0].as<int>();
    const std::int64_t observation = current[0][1].as<std::int64_t>();
    if (info.layer > 0 && observation > 0 && current_layer != info.layer) {
        throw AuthKeySessionLayerConflictError();
    }
    throw Error("update auth key client info: guarded update affected no row");
}

// Also cleans up any temp auth key that treats this key as its permanent
// key: the FK on temp_auth_key_bindings.temp_auth_key_id is ON DELETE
// CASCADE (deleting the temp key auto-clears its binding), but
// perm_auth_key_id is RESTRICT to prevent a dangling reference, so an
// explicit perm-key destroy must delete the associated temp key first.
//
// Remote authorization revocation must never call this: a kicked client
// must keep its protocol key so reconnecting reaches the RPC layer and gets
// AUTH_KEY_UNREGISTERED, not just a transport-level -404.
void AuthKeyStore::Delete(const std::array<std::uint8_t, 8>& id) {
    const std::int64_t key_id = detail::AuthKeyIDToInt64(id);
    detail::WithAuthIdentityTx(db_.conn(), "delete auth key", [&](pqxx::transaction_base& tx) {
        try {
            detail::LockRawAuthKeyInIdentityOrder(tx, key_id);
        } catch (const AuthKeyNotFoundError&) {
            return; // not found is a silent success
        }
        // The `(SELECT count(*) FROM deleted_temp) >= 0` clause below is
        // always true -- it exists only to give deleted_key a data
        // dependency on deleted_temp, forcing Postgres to sequence the temp
        // keys' delete before the permanent key's. Without it, the two
        // DELETEs have no ordering guarantee within one WITH statement, and
        // deleting the permanent row first would hit the RESTRICT FK on
        // temp_auth_key_bindings.perm_auth_key_id while its temp key (and
        // binding row) still exists.
        tx.exec(R"SQL(
WITH doomed_temp AS MATERIALIZED (
  SELECT temp_auth_key_id FROM temp_auth_key_bindings WHERE perm_auth_key_id = $1
), doomed_keys AS MATERIALIZED (
  SELECT $1::bigint AS auth_key_id
  UNION
  SELECT temp_auth_key_id FROM doomed_temp
), deleted_update_states AS (
  DELETE FROM update_states WHERE auth_key_id IN (SELECT auth_key_id FROM doomed_keys)
  RETURNING auth_key_id
), deleted_temp AS (
  DELETE FROM auth_keys WHERE auth_key_id IN (SELECT temp_auth_key_id FROM doomed_temp)
  RETURNING auth_key_id
)
DELETE FROM auth_keys
WHERE auth_key_id = $1
  AND (SELECT count(*) FROM deleted_temp) >= 0
)SQL",
                pqxx::params{key_id});
    });
}

} // namespace shuzagram::store::postgres
