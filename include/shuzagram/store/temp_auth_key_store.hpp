#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "shuzagram/domain/temp_auth_key.hpp"

// Port of the store.TempAuthKeyBindingStore interface
// (internal/store/temp_auth_key.go). Save (the SaveWithState-and-discard
// convenience wrapper) and DeleteExpired (the orphan-key GC sweep) are not
// ported: nothing in this project calls either yet.
namespace shuzagram::store {

class ITempAuthKeyBindingStore {
public:
    virtual ~ITempAuthKeyBindingStore() = default;

    // Atomically binds a temporary auth key to a permanent one and merges
    // their Layer defaults, re-validating both rows' current expiry/type
    // against the database (never trusting a caller's earlier read) in the
    // same transaction. Throws store::AuthKeyBindingInvalidError,
    // store::TempAuthKeyAlreadyBoundError, store::AuthKeySessionLayerInvalidError
    // or store::AuthKeySessionLayerConflictError.
    virtual domain::TempAuthKeyBindingResult SaveWithState(const domain::TempAuthKeyBinding& binding) = 0;

    virtual std::optional<domain::TempAuthKeyBinding> GetByTemp(const std::array<std::uint8_t, 8>& temp_auth_key_id) = 0;
};

} // namespace shuzagram::store
