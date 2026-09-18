// Manual smoke test for AuthKeyStore/AuthorizationStore against a real
// Postgres instance. Not run by `ctest` (needs live credentials); invoke:
//
//   SHUZAGRAM_PG_DSN="host=127.0.0.1 port=15432 dbname=telesrv_main \
//     user=telesrv password=..." ./build/tests/auth_store_smoke
//
// Creates one throwaway user and one throwaway permanent auth_keys row,
// drives the full AuthKeyStore/AuthorizationStore surface against them
// (including Bind's reject paths and its user_update_watermarks/
// user_update_retention/update_states baseline), and deletes everything it
// created. See user_store_smoke.cpp for the std::_Exit() libpqxx-teardown
// note.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/store/errors.hpp"
#include "shuzagram/store/postgres/auth_key_store.hpp"
#include "shuzagram/store/postgres/authorization_store.hpp"
#include "shuzagram/store/postgres/user_store.hpp"

namespace {

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what.c_str());
    }
}

std::array<std::uint8_t, 8> MakeAuthKeyID(std::int64_t seed) {
    std::array<std::uint8_t, 8> id{};
    std::memcpy(id.data(), &seed, 8);
    return id;
}

} // namespace

int main() {
    const char* dsn = std::getenv("SHUZAGRAM_PG_DSN");
    if (!dsn) {
        std::printf("SHUZAGRAM_PG_DSN not set, skipping live smoke test\n");
        return 0;
    }

    using namespace shuzagram;

    store::postgres::Database db(dsn);
    store::postgres::UserStore users(db);
    store::postgres::AuthKeyStore auth_keys(db);
    store::postgres::AuthorizationStore authorizations(db);

    const std::int64_t access_hash =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    domain::User draft;
    draft.access_hash = access_hash;
    draft.first_name = "AuthSmokeTest";
    const domain::User created_user = users.Create(draft);
    const std::int64_t user_id = created_user.id;
    std::printf("created throwaway user id=%lld\n", static_cast<long long>(user_id));

    const auto key_id = MakeAuthKeyID(access_hash);
    std::int64_t raw_key_id;
    std::memcpy(&raw_key_id, key_id.data(), 8);

    try {
        store::AuthKeyData key;
        key.id = key_id;
        key.value.fill(0x42); // deterministic filler, not real crypto
        key.server_salt = 123456789;
        key.expires_at = 0; // permanent
        key.device_model = "SmokeDevice";
        key.platform = "linux";
        auth_keys.Save(key);
        Check(true, "AuthKeyStore::Save persists a permanent key");

        const auto fetched = auth_keys.Get(key_id);
        Check(fetched.has_value() && fetched->server_salt == 123456789 && fetched->value == key.value,
              "AuthKeyStore::Get round-trips id/server_salt/body");

        store::AuthKeyClientInfo info;
        info.layer = 177;
        info.device_model = "SmokeDeviceV2";
        auth_keys.UpdateClientInfo(key_id, info);
        const auto after_info = auth_keys.Get(key_id);
        Check(after_info.has_value() && after_info->layer == 177 && after_info->device_model == "SmokeDeviceV2",
              "AuthKeyStore::UpdateClientInfo merges layer and device_model");

        const auto missing = authorizations.ByAuthKey(key_id);
        Check(!missing.has_value(), "ByAuthKey(unbound key) finds nothing before Bind");

        // Reject path: a temporary key can never be bound.
        {
            const auto temp_key_id = MakeAuthKeyID(access_hash + 1);
            std::int64_t raw_temp_id;
            std::memcpy(&raw_temp_id, temp_key_id.data(), 8);
            store::AuthKeyData temp_key;
            temp_key.id = temp_key_id;
            temp_key.value.fill(0x43);
            temp_key.expires_at = 3600; // temporary
            auth_keys.Save(temp_key);
            domain::Authorization temp_bind;
            temp_bind.auth_key_id = temp_key_id;
            temp_bind.user_id = user_id;
            temp_bind.password_pending = true;
            try {
                authorizations.Bind(temp_bind);
                Check(false, "Bind(temporary key) should throw AuthKeyNotPermanentError");
            } catch (const store::AuthKeyNotPermanentError&) {
                Check(true, "Bind(temporary key) throws AuthKeyNotPermanentError");
            }
            pqxx::work cleanup_temp(db.conn());
            cleanup_temp.exec("DELETE FROM auth_keys WHERE auth_key_id = $1", pqxx::params{raw_temp_id});
            cleanup_temp.commit();
        }

        // Reject path: a soft-deleted user can never be bound to.
        {
            domain::User deletable_draft;
            deletable_draft.access_hash = access_hash + 2;
            deletable_draft.first_name = "AuthSmokeDeletedTest";
            const domain::User deletable = users.Create(deletable_draft);
            {
                pqxx::work mark_deleted(db.conn());
                mark_deleted.exec("UPDATE users SET deleted_at = now(), deletion_source = 'manual', "
                                   "first_name = '', last_name = '', username = '', country_code = '', "
                                   "about = '', phone = ''"
                                   " WHERE id = $1",
                                   pqxx::params{deletable.id});
                mark_deleted.commit();
            }
            domain::Authorization deleted_bind;
            deleted_bind.auth_key_id = key_id;
            deleted_bind.user_id = deletable.id;
            deleted_bind.password_pending = true;
            try {
                authorizations.Bind(deleted_bind);
                Check(false, "Bind(deleted user) should throw AccountDeletedError");
            } catch (const domain::AccountDeletedError&) {
                Check(true, "Bind(deleted user) throws AccountDeletedError");
            }
            pqxx::work cleanup_deleted(db.conn());
            cleanup_deleted.exec("DELETE FROM users WHERE id = $1", pqxx::params{deletable.id});
            cleanup_deleted.commit();
        }

        // Happy path.
        domain::Authorization bind_request;
        bind_request.auth_key_id = key_id;
        bind_request.user_id = user_id;
        bind_request.device_model = "SmokeDevice";
        bind_request.platform = "linux";
        bind_request.password_pending = true;
        authorizations.Bind(bind_request);

        const auto bound = authorizations.ByAuthKey(key_id);
        Check(bound.has_value() && bound->user_id == user_id && bound->password_pending && bound->hash != 0,
              "Bind writes an authorization row with a non-zero computed hash");

        {
            pqxx::work check_tx(db.conn());
            const auto watermark =
                check_tx.exec("SELECT contiguous_pts FROM user_update_watermarks WHERE user_id = $1",
                               pqxx::params{user_id});
            const auto retention =
                check_tx.exec("SELECT retained_through_pts FROM user_update_retention WHERE user_id = $1",
                               pqxx::params{user_id});
            const auto state = check_tx.exec(
                "SELECT pts, qts, observed_pts FROM update_states WHERE auth_key_id = $1 AND user_id = $2",
                pqxx::params{raw_key_id, user_id});
            check_tx.commit();
            Check(!watermark.empty() && watermark[0][0].as<int>() == 0,
                  "Bind seeds user_update_watermarks at contiguous_pts=0 for a fresh user");
            Check(!retention.empty() && retention[0][0].as<int>() == 0,
                  "Bind seeds user_update_retention at retained_through_pts=0 for a fresh user");
            Check(!state.empty() && state[0][0].as<int>() == 0 && state[0][1].as<int>() == 0 &&
                      state[0][2].as<int>() == 0,
                  "Bind seeds this device's update_states baseline at pts=qts=observed_pts=0");
        }

        // Re-bind (e.g. a metadata refresh on the same auth key) hits ON
        // CONFLICT DO UPDATE and still succeeds without violating the pts
        // invariants just checked. Deliberately keeps password_pending
        // true: MarkPasswordPassed below still needs to find it pending.
        domain::Authorization rebind_request = bind_request;
        rebind_request.device_model = "SmokeDeviceRebound";
        authorizations.Bind(rebind_request);
        const auto rebound = authorizations.ByAuthKey(key_id);
        Check(rebound.has_value() && rebound->device_model == "SmokeDeviceRebound" && rebound->password_pending,
              "Re-Bind updates the existing row in place");

        domain::AuthKeyClientInfo client_info;
        client_info.layer = 200;
        client_info.device_model = "SmokeDeviceV3";
        client_info.ip = "203.0.113.1";
        authorizations.UpdateClientInfo(key_id, client_info);
        const auto after_client_info = authorizations.ByAuthKey(key_id);
        Check(after_client_info.has_value() && after_client_info->layer == 200 &&
                  after_client_info->device_model == "SmokeDeviceV3" && after_client_info->ip == "203.0.113.1",
              "AuthorizationStore::UpdateClientInfo merges layer/device_model/ip");

        const auto listed = authorizations.ListByUser(user_id);
        bool found_in_list = false;
        for (const auto& a : listed) {
            if (a.user_id == user_id) found_in_list = true;
        }
        Check(found_in_list, "ListByUser finds the seeded authorization");

        authorizations.MarkPasswordPassed(key_id, user_id);
        const auto after_password = authorizations.ByAuthKey(key_id);
        Check(after_password.has_value() && !after_password->password_pending,
              "MarkPasswordPassed clears password_pending");

        try {
            authorizations.MarkPasswordPassed(key_id, user_id);
            Check(false, "MarkPasswordPassed should throw when already not pending");
        } catch (const store::AuthorizationStateChangedError&) {
            Check(true, "MarkPasswordPassed throws AuthorizationStateChangedError when not pending");
        }

        const auto hash_of_row = after_password->hash;
        const auto revoked = authorizations.RevokeByHash(user_id, hash_of_row);
        Check(revoked.has_value() && revoked->user_id == user_id, "RevokeByHash removes the authorization row");
        Check(!authorizations.ByAuthKey(key_id).has_value(), "authorization row is gone after RevokeByHash");
        Check(auth_keys.Get(key_id).has_value(), "the protocol key itself survives RevokeByHash");

    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: unexpected exception: %s\n", e.what());
        ++g_failures;
    }

    pqxx::work cleanup(db.conn());
    // update_states has no FK to auth_keys/users (AuthKeyStore::Delete and
    // Bind both clean it explicitly instead), so it needs its own delete
    // here; user_update_watermarks/user_update_retention cascade off the
    // user delete below, and authorizations cascades off the auth_keys
    // delete.
    cleanup.exec("DELETE FROM update_states WHERE auth_key_id = $1", pqxx::params{raw_key_id});
    cleanup.exec("DELETE FROM auth_keys WHERE auth_key_id = $1", pqxx::params{raw_key_id});
    cleanup.exec("DELETE FROM users WHERE id = $1", pqxx::params{user_id});
    cleanup.commit();
    std::printf("cleaned up throwaway user id=%lld and auth key\n", static_cast<long long>(user_id));

    std::fflush(stdout);
    if (g_failures == 0) {
        std::printf("auth smoke test passed\n");
        std::fflush(stdout);
        std::_Exit(0);
    }
    std::fprintf(stderr, "%d auth smoke check(s) failed\n", g_failures);
    std::_Exit(1);
}
