// Manual smoke test for AuthKeyStore/AuthorizationStore against a real
// Postgres instance. Not run by `ctest` (needs live credentials); invoke:
//
//   SHUZAGRAM_PG_DSN="host=127.0.0.1 port=15432 dbname=telesrv_main \
//     user=telesrv password=..." ./build/tests/auth_store_smoke
//
// Creates one throwaway user and one throwaway permanent auth_keys row,
// drives AuthKeyStore and the non-Bind AuthorizationStore surface against
// them, and deletes both. See user_store_smoke.cpp for the std::_Exit()
// libpqxx-teardown note.

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

        domain::Authorization not_found_check;
        const auto missing = authorizations.ByAuthKey(key_id);
        Check(!missing.has_value(), "ByAuthKey(unbound key) finds nothing yet (Bind is not implemented)");

        try {
            authorizations.Bind(not_found_check);
            Check(false, "Bind should throw NotImplementedError");
        } catch (const domain::NotImplementedError&) {
            Check(true, "Bind throws NotImplementedError (update-baseline subsystem not ported)");
        }

        // Exercise the authorization row surface directly via raw SQL,
        // since Bind itself is deferred -- this still verifies ByAuthKey/
        // UpdateClientInfo/ListByUser/MarkPasswordPassed/Delete against a
        // real row shaped exactly like Bind would produce one.
        {
            pqxx::work tx(db.conn());
            tx.exec("INSERT INTO authorizations (auth_key_id, user_id, hash, password_pending) "
                    "VALUES ($1, $2, $3, true)",
                    pqxx::params{raw_key_id, user_id, static_cast<std::int64_t>(1)});
            tx.commit();
        }

        const auto bound = authorizations.ByAuthKey(key_id);
        Check(bound.has_value() && bound->user_id == user_id && bound->password_pending,
              "ByAuthKey finds the row seeded via raw SQL");

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
