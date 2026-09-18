#include "auth_identity_lock.hpp"

#include <sstream>

#include "shuzagram/store/errors.hpp"

namespace shuzagram::store::postgres::detail {

namespace {

bool IsRetryableSerializationError(const pqxx::sql_error& e) {
    const std::string_view code(e.sqlstate());
    return code == "40P01" || code == "40001"; // deadlock_detected, serialization_failure
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

struct AuthKeyIdentityHint {
    bool found = false;
    int expires_at = 0;
    bool bound = false;
    std::int64_t perm_id = 0;
    std::int64_t identity_id = 0;
    bool has_identity = false;
};

// lookupAuthKeyIdentityHint is intentionally lock-free. A positive-expiry
// raw key has no permanent identity until a binding is committed; a
// permanent raw key is its own identity. Callers must re-read after the raw
// row is locked.
AuthKeyIdentityHint LookupAuthKeyIdentityHint(pqxx::transaction_base& tx, std::int64_t raw_id) {
    const auto result = tx.exec(
        "SELECT key.expires_at, binding.temp_auth_key_id IS NOT NULL, "
        "COALESCE(binding.perm_auth_key_id, 0) "
        "FROM auth_keys AS key "
        "LEFT JOIN temp_auth_key_bindings AS binding ON binding.temp_auth_key_id = key.auth_key_id "
        "WHERE key.auth_key_id = $1",
        pqxx::params{raw_id});
    if (result.empty()) return {};
    AuthKeyIdentityHint hint;
    hint.found = true;
    hint.expires_at = result[0][0].as<int>();
    hint.bound = result[0][1].as<bool>();
    hint.perm_id = result[0][2].as<std::int64_t>();
    if (hint.bound) {
        hint.identity_id = hint.perm_id;
        hint.has_identity = true;
    } else if (hint.expires_at == 0) {
        hint.identity_id = raw_id;
        hint.has_identity = true;
    }
    return hint;
}

} // namespace

void WithAuthIdentityTx(pqxx::connection& conn, const std::string& op,
                         const std::function<void(pqxx::transaction_base&)>& fn) {
    for (int attempt = 0; attempt < kAuthIdentityTxMaxAttempts; ++attempt) {
        pqxx::work tx(conn);
        try {
            fn(tx);
            tx.commit();
            return;
        } catch (const AuthIdentityChangedException&) {
            continue; // tx destructor rolls back; retry with a fresh snapshot.
        } catch (const pqxx::sql_error& e) {
            if (attempt + 1 < kAuthIdentityTxMaxAttempts && IsRetryableSerializationError(e)) continue;
            throw;
        }
    }
    throw store::Error(op + " did not stabilize after " + std::to_string(kAuthIdentityTxMaxAttempts) + " attempts");
}

void LockPermanentAuthIdentities(pqxx::transaction_base& tx, const std::vector<std::int64_t>& perm_ids) {
    if (perm_ids.empty()) return;
    const auto result =
        tx.exec("SELECT DISTINCT hashint8(identity_id)::integer AS lock_key "
                "FROM unnest($1::bigint[]) AS identities(identity_id) ORDER BY lock_key",
                pqxx::params{BigintArrayLiteral(perm_ids)});
    for (const auto& row : result) {
        tx.exec("SELECT pg_advisory_xact_lock($1::integer, $2::integer)",
                pqxx::params{kAuthIdentityAdvisoryNamespace, row[0].as<std::int32_t>()});
    }
}

RawAuthKeyLock LockRawAuthKeyInIdentityOrder(pqxx::transaction_base& tx, std::int64_t raw_id) {
    const AuthKeyIdentityHint hint = LookupAuthKeyIdentityHint(tx, raw_id);
    if (!hint.found) throw store::AuthKeyNotFoundError();
    if (hint.has_identity) LockPermanentAuthIdentities(tx, {hint.identity_id});

    const auto raw_row =
        tx.exec("SELECT expires_at FROM auth_keys WHERE auth_key_id = $1 FOR UPDATE", pqxx::params{raw_id});
    if (raw_row.empty()) throw store::AuthKeyNotFoundError();
    const int raw_expiry = raw_row[0][0].as<int>();

    std::int64_t perm_id = raw_id;
    bool bound = false;
    const auto perm_row = tx.exec("SELECT perm_auth_key_id FROM temp_auth_key_bindings WHERE temp_auth_key_id = $1",
                                   pqxx::params{raw_id});
    if (!perm_row.empty()) {
        bound = true;
        perm_id = perm_row[0][0].as<std::int64_t>();
    }

    const bool actual_has_identity = bound || raw_expiry == 0;
    const std::int64_t actual_identity_id = perm_id;
    if (actual_has_identity != hint.has_identity ||
        (actual_has_identity && actual_identity_id != hint.identity_id) || bound != hint.bound ||
        raw_expiry != hint.expires_at) {
        throw AuthIdentityChangedException();
    }
    if (!bound) return RawAuthKeyLock{raw_expiry, perm_id, false};

    const auto perm_lock_row =
        tx.exec("SELECT expires_at FROM auth_keys WHERE auth_key_id = $1 FOR UPDATE", pqxx::params{perm_id});
    if (perm_lock_row.empty()) throw store::AuthKeyBindingInvalidError();
    const int perm_expiry = perm_lock_row[0][0].as<int>();
    if (raw_expiry <= 0 || perm_expiry != 0) throw store::AuthKeyBindingInvalidError();
    return RawAuthKeyLock{raw_expiry, perm_id, true};
}

} // namespace shuzagram::store::postgres::detail
