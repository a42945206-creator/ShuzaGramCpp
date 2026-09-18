#pragma once

#include "shuzagram/store/postgres/database.hpp"
#include "shuzagram/store/temp_auth_key_store.hpp"

namespace shuzagram::store::postgres {

// PostgreSQL implementation of store::ITempAuthKeyBindingStore, ported from
// internal/store/postgres/temp_auth_key.go. SaveWithState calls the SAME
// `telesrv_bind_temp_auth_key` database function the live ShuzaGram
// deployment's Go binary calls (added by migration
// 0199_temp_auth_key_bind_function) -- this project doesn't re-implement
// that atomic identity-lock-respecting logic in C++, it reuses the
// already-deployed, already-correct database-side implementation.
class TempAuthKeyBindingStore final : public store::ITempAuthKeyBindingStore {
public:
    explicit TempAuthKeyBindingStore(Database& db) : db_(db) {}

    domain::TempAuthKeyBindingResult SaveWithState(const domain::TempAuthKeyBinding& binding) override;
    std::optional<domain::TempAuthKeyBinding> GetByTemp(const std::array<std::uint8_t, 8>& temp_auth_key_id) override;

private:
    Database& db_;
};

} // namespace shuzagram::store::postgres
