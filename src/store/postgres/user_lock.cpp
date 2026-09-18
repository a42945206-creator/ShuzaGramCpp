#include "user_lock.hpp"

#include <algorithm>
#include <sstream>

namespace shuzagram::store::postgres::detail {

void LockUsersForUpdate(pqxx::transaction_base& tx, const std::vector<std::int64_t>& user_ids) {
    std::vector<std::int64_t> unique;
    unique.reserve(user_ids.size());
    for (const std::int64_t id : user_ids) {
        if (id <= 0) continue;
        if (std::find(unique.begin(), unique.end(), id) != unique.end()) continue;
        unique.push_back(id);
    }
    if (unique.empty()) return;

    std::ostringstream literal;
    literal << '{';
    for (std::size_t i = 0; i < unique.size(); ++i) {
        if (i) literal << ',';
        literal << unique[i];
    }
    literal << '}';
    tx.exec("SELECT pg_advisory_xact_lock(requested.user_id) "
            "FROM unnest($1::bigint[]) AS requested(user_id) ORDER BY requested.user_id",
            pqxx::params{literal.str()});
}

} // namespace shuzagram::store::postgres::detail
