#pragma once

#include "shuzagram/store/auth_key_store.hpp"
#include "shuzagram/store/postgres/database.hpp"

namespace shuzagram::store::postgres {

// PostgreSQL implementation of store::IAuthKeyStore, ported from
// internal/store/postgres/authkey.go against the live `auth_keys` table.
// See store::IAuthKeyStore for what's still deferred (orphan-key GC).
class AuthKeyStore final : public store::IAuthKeyStore {
public:
    explicit AuthKeyStore(Database& db) : db_(db) {}

    void Save(const store::AuthKeyData& key) override;
    std::optional<store::AuthKeyData> Get(const std::array<std::uint8_t, 8>& id) override;
    void UpdateClientInfo(const std::array<std::uint8_t, 8>& id, const store::AuthKeyClientInfo& info) override;
    void Delete(const std::array<std::uint8_t, 8>& id) override;
    std::optional<store::AuthKeyData> Revalidate(const std::array<std::uint8_t, 8>& id) override;
    store::AuthKeyBindingKeys LoadBindingKeys(const std::array<std::uint8_t, 8>& temp_id,
                                               const std::array<std::uint8_t, 8>& perm_id) override;

private:
    Database& db_;
};

} // namespace shuzagram::store::postgres
