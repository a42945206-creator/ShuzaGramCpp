#pragma once

#include <cstdint>
#include <vector>

#include <pqxx/pqxx>

// Port of lockUsersForUpdate (internal/store/postgres/message_send.go:957).
// General-purpose: takes a single advisory lock per distinct positive user
// id, in ascending order, for the lifetime of the transaction. Used
// wherever a mutation needs to serialize against everything else touching
// the same user row(s) without taking a real row lock on `users` itself.
namespace shuzagram::store::postgres::detail {

void LockUsersForUpdate(pqxx::transaction_base& tx, const std::vector<std::int64_t>& user_ids);

inline void LockUserForUpdate(pqxx::transaction_base& tx, std::int64_t user_id) {
    LockUsersForUpdate(tx, {user_id});
}

} // namespace shuzagram::store::postgres::detail
