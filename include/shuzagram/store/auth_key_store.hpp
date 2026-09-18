#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "shuzagram/store/auth_key.hpp"

// Port of the store.AuthKeyStore interface (internal/store/authkey.go).
// Save/Get/UpdateClientInfo/Delete/Revalidate/LoadBindingKeys are
// implemented against Postgres. TouchActiveRawAuthKeys and DeleteOrphaned
// (the orphan-key GC sweep) remain deferred: nothing in this project calls
// them yet, and porting them without a caller to exercise them would be
// unverifiable.
namespace shuzagram::store {

class IAuthKeyStore {
public:
    virtual ~IAuthKeyStore() = default;

    // Persists one auth key record. A retry with the same ID may only keep
    // the key body and protocol type/expiry unchanged. Throws
    // InvalidAuthKeyProtocolExpiryError or AuthKeyProtocolMetadataConflictError.
    virtual void Save(const AuthKeyData& key) = 0;

    // Looks up by auth_key_id and refreshes the durable orphan-activity
    // lease. Used only when a physical connection first acquires the key,
    // or another boundary that genuinely needs to establish a new lease.
    virtual std::optional<AuthKeyData> Get(const std::array<std::uint8_t, 8>& id) = 0;

    // Merge-updates the client negotiation metadata. Empty fields don't
    // overwrite existing values; layer/api_id == 0 don't overwrite either.
    // Throws AuthKeyNotFoundError if id doesn't name a live key -- a missing
    // primary must never be treated as a successful update to a mirror.
    virtual void UpdateClientInfo(const std::array<std::uint8_t, 8>& id, const AuthKeyClientInfo& info) = 0;

    // destroy_auth_key. Not-found is a silent success. The session-manager /
    // control fabric is responsible for fencing the active connection.
    virtual void Delete(const std::array<std::uint8_t, 8>& id) = 0;

    // Plain read, WITHOUT touching the orphan-activity lease -- used only to
    // re-classify an already-failed auth.bindTempAuthKey attempt (was the
    // temp key simply gone/expired, or was the proof itself bad?). Never
    // use this for the initial lookup that gates whether a key may still be
    // used; Get is the one that keeps a live key's lease current.
    virtual std::optional<AuthKeyData> Revalidate(const std::array<std::uint8_t, 8>& id) = 0;

    // Loads and activity-touches both cryptographic proof keys named by one
    // auth.bindTempAuthKey call in a single statement, so orphan GC can
    // never split proof validation across two independently-expiring
    // leases. Missing rows stay explicit in the result (found flags) rather
    // than throwing, since "which key was missing" changes which public RPC
    // error the caller returns.
    virtual AuthKeyBindingKeys LoadBindingKeys(const std::array<std::uint8_t, 8>& temp_id,
                                                const std::array<std::uint8_t, 8>& perm_id) = 0;
};

} // namespace shuzagram::store
