#pragma once

#include <array>
#include <cstdint>
#include <vector>

// Faithful port of internal/domain/temp_auth_key.go.
namespace shuzagram::domain {

// TempAuthKeyBinding is the persisted record of one auth.bindTempAuthKey.
struct TempAuthKeyBinding {
    std::array<std::uint8_t, 8> temp_auth_key_id{};
    std::int64_t perm_auth_key_id = 0;
    std::int64_t nonce = 0;
    std::int64_t temp_session_id = 0;
    int expires_at = 0;
    std::vector<std::uint8_t> encrypted_message;
};

// TempAuthKeyBindingResult is the exact auth-key Layer default committed by
// the temp-to-permanent binding transaction. layer_observation_id is the
// durable ordering token; zero denotes the legacy/unordered default.
struct TempAuthKeyBindingResult {
    int layer = 0;
    std::int64_t layer_observation_id = 0;
};

} // namespace shuzagram::domain
