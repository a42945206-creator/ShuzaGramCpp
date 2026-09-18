#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "shuzagram/store/errors.hpp"

// Port of internal/store/authkey.go's package-level types, constants and
// pure functions (the AuthKeyStore *interface* itself is
// shuzagram::store::IAuthKeyStore in auth_key_store.hpp; this header is the
// data shapes it moves).
namespace shuzagram::store {

// Only permanent(0) or a positive TL int32-range temporary expiry may be
// written by a new handshake. -1 may only be written by migration 0086
// (a historical row whose type cannot be proven).
inline bool ValidNewAuthKeyProtocolExpiry(int expires_at) {
    return expires_at >= 0 && static_cast<std::int64_t>(expires_at) <= std::numeric_limits<std::int32_t>::max();
}

// AuthKeyData is one persisted MTProto auth key record. Deliberately
// independent of any TL/td protocol type: the transport layer converts
// between its own AuthKey representation and this at the boundary.
struct AuthKeyData {
    std::array<std::uint8_t, 8> id{};   // auth_key_id (low 64 bits of the key's SHA1)
    std::array<std::uint8_t, 256> value{}; // 2048-bit auth key
    std::int64_t server_salt = 0;       // initial server salt produced by the key exchange
    std::int64_t created_at = 0;        // Unix seconds

    // expires_at is the protocol expiry (Unix seconds) of a
    // temporary/media-temporary auth key. 0 means permanent only; -1 means a
    // historical migration-0086 row whose type cannot be proven -- the edge
    // must reject it with -404 and force a re-handshake. Key type is a
    // handshake fact and must never be inferred from whether an
    // authorization exists.
    int expires_at = 0;
    int layer = 0;
    // layer_observation_id globally orders durable explicit Layer
    // observations across sessions, processes and restarts. Zero means
    // legacy/no ordered evidence; still a usable inherited default, but it
    // can never outrank a positive observation during temp-to-perm identity
    // merge.
    std::int64_t layer_observation_id = 0;
    std::string device_model;
    std::string platform;
    std::string system_version;
    int api_id = 0;
    std::string app_version;
    // User binding is not here: auth_key is a protocol artifact. Binding
    // (auth_key <-> user + device info) is carried by Authorization.
};

struct AuthKeyClientInfo {
    // layer is the durable last-known default. The RPC boundary validates it
    // against the generated profile set before use; stores must preserve
    // the exact value and must never clamp a future unsupported Layer.
    int layer = 0;
    std::string device_model;
    std::string platform;
    std::string system_version;
    int api_id = 0;
    std::string app_version;
};

// The authoritative pair used to verify one auth.bindTempAuthKey proof.
// Stores load and activity-touch both requested rows in one database
// statement so orphan collection cannot split proof validation across two
// independent leases.
struct AuthKeyBindingKeys {
    AuthKeyData temporary;
    bool temporary_found = false;
    AuthKeyData permanent;
    bool permanent_found = false;
};

// Resolves the inherited default when a raw temporary key is bound to its
// permanent identity. Positive observation IDs are globally ordered durable
// evidence. Equal positive IDs must describe the same Layer; zero is
// legacy/unordered and therefore defers to the permanent identity.
inline void MergeAuthKeyLayerObservations(int temp_layer, std::int64_t temp_observation_id, int perm_layer,
                                           std::int64_t perm_observation_id, int& layer,
                                           std::int64_t& observation_id) {
    if (temp_layer < 0 || perm_layer < 0 || temp_observation_id < 0 || perm_observation_id < 0 ||
        (temp_observation_id > 0 && temp_layer == 0) || (perm_observation_id > 0 && perm_layer == 0)) {
        throw AuthKeySessionLayerInvalidError();
    }
    if (temp_observation_id > perm_observation_id) {
        layer = temp_layer;
        observation_id = temp_observation_id;
    } else if (perm_observation_id > temp_observation_id) {
        layer = perm_layer;
        observation_id = perm_observation_id;
    } else if (temp_observation_id > 0 && temp_layer != perm_layer) {
        throw AuthKeySessionLayerConflictError();
    } else if (temp_observation_id > 0) {
        layer = temp_layer;
        observation_id = temp_observation_id;
    } else {
        layer = perm_layer;
        observation_id = 0;
    }
}

} // namespace shuzagram::store
