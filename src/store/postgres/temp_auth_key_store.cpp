#include "shuzagram/store/postgres/temp_auth_key_store.hpp"

#include <cstring>
#include <limits>

#include "auth_identity_lock.hpp"
#include "auth_key_codec.hpp"
#include "shuzagram/store/errors.hpp"

// Ported from internal/store/postgres/temp_auth_key.go.
namespace shuzagram::store::postgres {

using detail::AuthKeyIDFromInt64;
using detail::AuthKeyIDToInt64;

domain::TempAuthKeyBindingResult TempAuthKeyBindingStore::SaveWithState(const domain::TempAuthKeyBinding& binding) {
    if (binding.expires_at <= 0 || binding.expires_at > std::numeric_limits<std::int32_t>::max()) {
        throw AuthKeyBindingInvalidError();
    }

    domain::TempAuthKeyBindingResult result;
    detail::WithAuthIdentityTx(db_.conn(), "save temp auth key binding", [&](pqxx::transaction_base& tx) {
        std::string status;
        int merged_layer = 0;
        std::int64_t merged_observation_id = 0;
        try {
            const auto row = tx.exec(
                                      "/* temp_auth_key_bind_atomic */ "
                                      "SELECT bind_status, merged_layer, merged_observation_id "
                                      "FROM public.telesrv_bind_temp_auth_key($1, $2, $3, $4, $5, $6)",
                                      pqxx::params{AuthKeyIDToInt64(binding.temp_auth_key_id), binding.perm_auth_key_id,
                                                   binding.nonce, binding.temp_session_id, binding.expires_at,
                                                   pqxx::binary_cast(binding.encrypted_message)})[0];
            status = row[0].as<std::string>();
            merged_layer = row[1].as<int>();
            merged_observation_id = row[2].as<std::int64_t>();
        } catch (const pqxx::foreign_key_violation&) {
            throw AuthKeyBindingInvalidError();
        }

        if (status == "ok") {
            if (merged_layer < 0 || merged_observation_id < 0 || (merged_observation_id > 0 && merged_layer == 0)) {
                throw store::Error("bind temporary auth key atomically: invalid result layer/observation");
            }
            result.layer = merged_layer;
            result.layer_observation_id = merged_observation_id;
        } else if (status == "already_bound") {
            throw TempAuthKeyAlreadyBoundError();
        } else if (status == "binding_invalid") {
            throw AuthKeyBindingInvalidError();
        } else if (status == "layer_invalid") {
            throw AuthKeySessionLayerInvalidError();
        } else if (status == "layer_conflict") {
            throw AuthKeySessionLayerConflictError();
        } else {
            throw store::Error("bind temporary auth key atomically: unknown status " + status);
        }
    });
    return result;
}

std::optional<domain::TempAuthKeyBinding> TempAuthKeyBindingStore::GetByTemp(
    const std::array<std::uint8_t, 8>& temp_auth_key_id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        "SELECT temp_auth_key_id, perm_auth_key_id, nonce, temp_session_id, expires_at, encrypted_message "
        "FROM temp_auth_key_bindings WHERE temp_auth_key_id = $1",
        pqxx::params{AuthKeyIDToInt64(temp_auth_key_id)});
    tx.commit();
    if (result.empty()) return std::nullopt;

    const auto& row = result[0];
    domain::TempAuthKeyBinding binding;
    binding.temp_auth_key_id = AuthKeyIDFromInt64(row[0].as<std::int64_t>());
    binding.perm_auth_key_id = row[1].as<std::int64_t>();
    binding.nonce = row[2].as<std::int64_t>();
    binding.temp_session_id = row[3].as<std::int64_t>();
    binding.expires_at = row[4].as<int>();
    const auto message = row[5].as<pqxx::bytes>();
    binding.encrypted_message.resize(message.size());
    std::memcpy(binding.encrypted_message.data(), message.data(), message.size());
    return binding;
}

} // namespace shuzagram::store::postgres
