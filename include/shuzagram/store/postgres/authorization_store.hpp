#pragma once

#include "shuzagram/store/authorization_store.hpp"
#include "shuzagram/store/postgres/database.hpp"

namespace shuzagram::store::postgres {

// PostgreSQL implementation of store::IAuthorizationStore, ported from
// internal/store/postgres/authorization.go. RevokeByHash and
// RevokeByUserExcept are extra methods beyond the store.AuthorizationStore
// Go interface (used directly by the higher-level session-termination
// service), kept here for the same reason.
class AuthorizationStore final : public store::IAuthorizationStore {
public:
    explicit AuthorizationStore(Database& db) : db_(db) {}

    void Bind(const domain::Authorization& a) override;
    std::optional<domain::Authorization> ByAuthKey(const std::array<std::uint8_t, 8>& auth_key_id) override;
    void UpdateClientInfo(const std::array<std::uint8_t, 8>& auth_key_id,
                           const domain::AuthKeyClientInfo& info) override;
    std::vector<domain::Authorization> ListByUser(std::int64_t user_id) override;
    void Delete(const std::array<std::uint8_t, 8>& auth_key_id) override;
    std::optional<domain::Authorization> DeleteByHash(std::int64_t user_id, std::int64_t hash) override;
    std::vector<domain::Authorization> DeleteByUserExcept(std::int64_t user_id,
                                                           const std::array<std::uint8_t, 8>& keep_auth_key_id) override;
    void MarkPasswordPassed(const std::array<std::uint8_t, 8>& auth_key_id, std::int64_t expected_user_id) override;

    // Remote kick-device entry point: deletes the business authorization and
    // device update state but keeps the permanent/temp protocol key and
    // binding, so a kicked client can still complete MTProto decryption on
    // reconnect and the RPC gate returns AUTH_KEY_UNREGISTERED (deleting the
    // protocol key first would only give the client a transport -404, with
    // no reliable way to clean up its local login state).
    std::optional<domain::Authorization> RevokeByHash(std::int64_t user_id, std::int64_t hash);

    // Same kind of revoke, batched over every authorization for user_id
    // except keep_auth_key_id.
    std::vector<domain::Authorization> RevokeByUserExcept(std::int64_t user_id,
                                                           const std::array<std::uint8_t, 8>& keep_auth_key_id);

private:
    Database& db_;
};

} // namespace shuzagram::store::postgres
