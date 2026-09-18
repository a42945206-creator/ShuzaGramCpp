#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include <pqxx/pqxx>

// Port of internal/store/postgres/auth_identity_lock.go. Shared by
// AuthKeyStore::Delete and every AuthorizationStore mutation that touches
// more than one auth_keys row, so that bind/delete/revoke can never deadlock
// against each other by locking the same permanent identity in opposite
// orders.
namespace shuzagram::store::postgres::detail {

// Two-int32 advisory-lock namespace, deliberately disjoint from any
// single-bigint advisory lock used elsewhere in the store. AUTH in ASCII, so
// it stays recognizable in pg_locks diagnostics.
inline constexpr std::int32_t kAuthIdentityAdvisoryNamespace = 0x41555448;
inline constexpr int kAuthIdentityTxMaxAttempts = 3;

// Internal-only retry signal: the application-visible identity of a raw
// auth_key changed between the lock-free hint read and the row lock. Never
// escapes WithAuthIdentityTx.
class AuthIdentityChangedException : public std::exception {
public:
    const char* what() const noexcept override { return "auth key permanent identity changed while acquiring locks"; }
};

// Gives identity-sensitive stores an explicit transaction boundary,
// retrying up to kAuthIdentityTxMaxAttempts times on
// AuthIdentityChangedException (a fresh pqxx::work each time -- a failed
// transaction can't be reused) or a Postgres deadlock/serialization error
// (40P01/40001).
void WithAuthIdentityTx(pqxx::connection& conn, const std::string& op,
                         const std::function<void(pqxx::transaction_base&)>& fn);

// Acquires the complete batch of permanent-identity advisory locks before
// any auth-key, binding, authorization or update-state row lock. Ordering is
// by the final int32 hashint8 key (not the source bigint identity): hash
// collisions are intentionally one lock and so can never create an opposite
// acquisition order.
void LockPermanentAuthIdentities(pqxx::transaction_base& tx, const std::vector<std::int64_t>& perm_ids);

// Establishes the only cross-identity row-lock order used by bind, selector
// advance and direct key deletion:
//
//   permanent identity advisory gate -> raw auth-key row -> permanent row
//
// Throws store::AuthKeyNotFoundError if raw_id doesn't exist, or
// AuthIdentityChangedException if an initially-unbound temp key became bound
// before the raw lock was acquired (the caller must let this propagate to
// WithAuthIdentityTx and retry).
struct RawAuthKeyLock {
    int raw_expiry = 0;
    std::int64_t perm_id = 0;
    bool bound = false;
};
RawAuthKeyLock LockRawAuthKeyInIdentityOrder(pqxx::transaction_base& tx, std::int64_t raw_id);

} // namespace shuzagram::store::postgres::detail
