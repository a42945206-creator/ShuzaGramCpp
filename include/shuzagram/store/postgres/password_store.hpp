#pragma once

#include "shuzagram/store/password_store.hpp"
#include "shuzagram/store/postgres/database.hpp"

namespace shuzagram::store::postgres {

// PostgreSQL implementation of store::IPasswordStore against the live
// `account_passwords` table, ported from internal/store/postgres/account.go
// (the PasswordStore-relevant methods only -- that Go struct also backs
// several unrelated interfaces this project doesn't touch).
//
// Columns this project doesn't track (login_email, email_unconfirmed_
// pattern, login_email_pattern, recovery_email, password_changed_at) are
// always written as empty/NULL -- see store::IPasswordStore's own doc
// comment for why (no email-login flow in this port).
class PasswordStore final : public store::IPasswordStore {
public:
    explicit PasswordStore(Database& db) : db_(db) {}

    std::optional<domain::PasswordSettings> GetByUser(std::int64_t user_id) override;
    void Save(std::int64_t user_id, const domain::PasswordSettings& settings) override;

private:
    Database& db_;
};

} // namespace shuzagram::store::postgres
