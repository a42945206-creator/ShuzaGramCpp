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

#include "shuzagram/auth/bind_temp_auth_key.hpp"
#include "shuzagram/auth/check_password.hpp"
#include "shuzagram/auth/sign_in.hpp"
#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/mtproto/crypto/bind.hpp"
#include "shuzagram/mtproto/crypto/srp.hpp"
#include "shuzagram/store/errors.hpp"
#include "shuzagram/store/memory/code_store.hpp"
#include "shuzagram/store/postgres/auth_key_store.hpp"
#include "shuzagram/store/postgres/authorization_store.hpp"
#include "shuzagram/store/postgres/password_store.hpp"
#include "shuzagram/store/postgres/temp_auth_key_store.hpp"
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

        // auth.bindTempAuthKey coverage: LoadBindingKeys, the atomic
        // Postgres `telesrv_bind_temp_auth_key` function via
        // TempAuthKeyBindingStore, and the auth::BindTempAuthKey
        // business-logic layer on top of both -- against the SAME live
        // schema the real ShuzaGram deployment's Go binary uses (this
        // reuses that already-deployed database function rather than
        // reimplementing its identity-lock-respecting logic in C++). key_id
        // (still a live permanent key at this point) plays the permanent
        // key here.
        {
            store::postgres::TempAuthKeyBindingStore temp_keys(db);

            const auto temp_id = MakeAuthKeyID(access_hash + 3);
            std::int64_t raw_temp_id;
            std::memcpy(&raw_temp_id, temp_id.data(), 8);
            const int expires_at =
                static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count()) +
                3600;
            store::AuthKeyData temp_key;
            temp_key.id = temp_id;
            temp_key.value.fill(0x44);
            temp_key.expires_at = expires_at;
            auth_keys.Save(temp_key);

            const auto pair = auth_keys.LoadBindingKeys(temp_id, key_id);
            Check(pair.temporary_found && pair.temporary.expires_at == expires_at && pair.permanent_found &&
                      pair.permanent.expires_at == 0,
                  "LoadBindingKeys returns both rows with their real expiry");

            mtproto::messages::BindAuthKeyInner inner;
            inner.nonce = 0x0102030405060708;
            inner.temp_auth_key_id = raw_temp_id;
            inner.perm_auth_key_id = raw_key_id;
            inner.temp_session_id = 999;
            inner.expires_at = expires_at;
            const auto encrypted = mtproto::crypto::EncryptBindMessage(key.value, /*msg_id=*/1, inner);

            auth::BindTempAuthKeyRequest req;
            req.temp_auth_key_id = temp_id;
            req.temp_session_id = 999;
            req.perm_auth_key_id = raw_key_id;
            req.nonce = inner.nonce;
            req.expires_at = expires_at;
            req.encrypted_message = encrypted;

            // key_id already carries layer=177 from the UpdateClientInfo
            // check earlier in this test; a fresh temp key with no Layer
            // evidence of its own inherits that as the merged default (see
            // store::MergeAuthKeyLayerObservations / the SQL function's
            // identical logic).
            const auto result = auth::BindTempAuthKey(auth_keys, temp_keys, req);
            Check(result.layer == 177,
                  "BindTempAuthKey happy path succeeds against the live telesrv_bind_temp_auth_key");

            const auto stored = temp_keys.GetByTemp(temp_id);
            Check(stored.has_value() && stored->perm_auth_key_id == raw_key_id && stored->temp_session_id == 999 &&
                      stored->nonce == inner.nonce,
                  "GetByTemp reads back the persisted binding");

            const auto merged_temp = auth_keys.Get(temp_id);
            const auto merged_perm = auth_keys.Get(key_id);
            Check(merged_temp.has_value() && merged_perm.has_value() && merged_temp->layer == merged_perm->layer,
                  "the bind function merges the same Layer default onto both rows");

            try {
                auth::BindTempAuthKeyRequest tampered = req;
                tampered.nonce = req.nonce + 1; // no longer matches the encrypted proof
                auth::BindTempAuthKey(auth_keys, temp_keys, tampered);
                Check(false, "a request whose fields don't match the decrypted proof should be rejected");
            } catch (const auth::EncryptedMessageInvalidError&) {
                Check(true, "field mismatch against the decrypted proof throws EncryptedMessageInvalidError");
            }

            pqxx::work cleanup_temp(db.conn());
            // temp_auth_key_bindings has ON DELETE CASCADE from
            // temp_auth_key_id, so deleting the temp key alone is enough.
            cleanup_temp.exec("DELETE FROM auth_keys WHERE auth_key_id = $1", pqxx::params{raw_temp_id});
            cleanup_temp.commit();
        }

        // auth.sendCode -> auth.signIn -> auth.signUp -> auth.signIn again,
        // against the REAL UserStore/AuthorizationStore (this is where the
        // fake-store ctest coverage in auth_sign_in_test.cpp can't reach:
        // real phone-uniqueness, real Bind pts-baseline seeding, and a
        // real second Bind re-authorizing the same auth_key_id). CodeStore
        // itself is the in-memory implementation either way -- it has no
        // Postgres dependency to verify here.
        {
            store::memory::CodeStore codes;

            const auto signin_key_id = MakeAuthKeyID(access_hash + 4);
            std::int64_t raw_signin_key_id;
            std::memcpy(&raw_signin_key_id, signin_key_id.data(), 8);
            store::AuthKeyData signin_key;
            signin_key.id = signin_key_id;
            signin_key.value.fill(0x55);
            signin_key.expires_at = 0; // permanent
            auth_keys.Save(signin_key);

            // "888" virtual identities accept 7-15 canonical digits (see
            // domain/phone.hpp) -- a real-looking E.164 number would need
            // country-aware parsing this test doesn't want to depend on.
            const std::string phone = "888" + std::to_string(static_cast<std::uint64_t>(access_hash) % 100000000ULL);

            domain::Authorization auth_template;
            auth_template.auth_key_id = signin_key_id;

            const auto hash1 = auth::SendCode(users, codes, phone);
            const auto first_sign_in =
                auth::SignIn(users, authorizations, codes, auth_template, phone, hash1, "12345");
            Check(first_sign_in.need_sign_up, "SignIn on a brand-new phone reports need_sign_up");
            Check(!authorizations.ByAuthKey(signin_key_id).has_value(),
                  "need_sign_up path does not bind any authorization yet (live store)");

            const auto signed_up = auth::SignUp(users, authorizations, codes, auth_template, phone, hash1,
                                                 "AuthSmokeSignUp", "");
            Check(signed_up.phone == phone && signed_up.first_name == "AuthSmokeSignUp",
                  "SignUp creates a real user row with the normalized phone");
            const auto bound1 = authorizations.ByAuthKey(signin_key_id);
            Check(bound1.has_value() && bound1->user_id == signed_up.id,
                  "SignUp binds the authorization to the new user (live store)");

            const auto hash2 = auth::SendCode(users, codes, phone);
            const auto second_sign_in =
                auth::SignIn(users, authorizations, codes, auth_template, phone, hash2, "12345");
            Check(!second_sign_in.need_sign_up && second_sign_in.user.id == signed_up.id,
                  "SignIn on the now-registered phone finds the same user and does not need sign-up");
            const auto bound2 = authorizations.ByAuthKey(signin_key_id);
            Check(bound2.has_value() && bound2->user_id == signed_up.id,
                  "the second SignIn re-binds the same authorization row");

            pqxx::work cleanup_signin(db.conn());
            cleanup_signin.exec("DELETE FROM update_states WHERE auth_key_id = $1", pqxx::params{raw_signin_key_id});
            cleanup_signin.exec("DELETE FROM auth_keys WHERE auth_key_id = $1", pqxx::params{raw_signin_key_id});
            cleanup_signin.exec("DELETE FROM users WHERE id = $1", pqxx::params{signed_up.id});
            cleanup_signin.commit();
        }

        // auth.checkPassword / account.getPassword coverage against the
        // real `account_passwords` table: seed a password row (the "test
        // fixture recipe" from the SRP research -- this project doesn't
        // implement account.updatePasswordSettings, so a real client
        // can't set one through the RPC layer yet), then drive
        // auth::GetPassword (rolls+persists a live SRP challenge) and
        // auth::CheckPassword (verifies a genuine client proof) against it.
        {
            store::postgres::PasswordStore passwords(db);
            const auto password = std::vector<std::uint8_t>{'h', 'u', 'n', 't', 'e', 'r', '2'};

            std::vector<std::uint8_t> salt1 = {0xEC, 0xF8, 0x73, 0x76, 0x65, 0xBC, 0x77, 0x5A}; // baseSalt1
            for (int i = 0; i < 32; ++i) salt1.push_back(static_cast<std::uint8_t>(access_hash >> (i % 8)));
            const auto salt2 = mtproto::crypto::SrpBaseSalt2();

            domain::PasswordAlgo algo;
            algo.salt1 = salt1;
            algo.salt2 = salt2;
            algo.g = mtproto::crypto::kSrpBaseG;
            algo.p = mtproto::crypto::SrpBaseP();

            domain::PasswordSettings settings = auth::DefaultPasswordSettings();
            settings.has_password = true;
            settings.current_algo = algo;
            settings.srp_verifier = mtproto::crypto::SrpComputeVerifier(password, salt1, salt2);
            passwords.Save(user_id, settings);

            const auto fetched_before = passwords.GetByUser(user_id);
            Check(fetched_before.has_value() && fetched_before->has_password && fetched_before->srp_id == 0,
                  "a directly-seeded password row round-trips through Postgres with srp_id still unassigned");

            const auto rolled = auth::GetPassword(passwords, user_id);
            Check(rolled.srp_id != 0 && !rolled.srp_b.empty() && !rolled.srp_b_secret.empty(),
                  "auth::GetPassword rolls and persists a live SRP challenge against the real table");
            const auto fetched_after = passwords.GetByUser(user_id);
            Check(fetched_after.has_value() && fetched_after->srp_b == rolled.srp_b &&
                      fetched_after->srp_id == rolled.srp_id,
                  "the rolled challenge is genuinely persisted, not just returned in-memory");

            const auto client_random = std::vector<std::uint8_t>(256, 0x09);
            const auto proof = mtproto::crypto::SrpClientProof(password, salt1, salt2, rolled.srp_b, client_random);
            domain::PasswordCheck check;
            check.srp_id = rolled.srp_id;
            check.a = proof.a;
            check.m1 = proof.m1;
            try {
                auth::CheckPassword(passwords, user_id, check);
                Check(true, "auth::CheckPassword accepts a genuine client proof against the live table");
            } catch (const std::exception& e) {
                Check(false, std::string("auth::CheckPassword unexpectedly threw: ") + e.what());
            }

            domain::PasswordCheck wrong_check = check;
            wrong_check.m1.back() ^= 0x01;
            try {
                auth::CheckPassword(passwords, user_id, wrong_check);
                Check(false, "a tampered M1 against the live table should throw");
            } catch (const auth::PasswordHashInvalidError&) {
                Check(true, "auth::CheckPassword rejects a tampered M1 against the live table");
            }

            pqxx::work cleanup_password(db.conn());
            cleanup_password.exec("DELETE FROM account_passwords WHERE user_id = $1", pqxx::params{user_id});
            cleanup_password.commit();
        }

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
