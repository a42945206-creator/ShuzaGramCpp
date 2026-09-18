#pragma once

#include <cstdint>
#include <vector>

#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for auth.bindTempAuthKey. Field order and type ids copied
// directly from gotd/td: BindAuthKeyInner is hand-written in crypto/bind.go
// (a crypto-layer type, not code-generated like ordinary tg.* RPC objects),
// AuthBindTempAuthKeyRequest is generated into
// tg/tl_auth_bind_temp_auth_key_gen.go. See crypto/bind.hpp for how
// BindAuthKeyInner is wrapped into/unwrapped from the request's
// encrypted_message, and NOTES/bind-temp-auth-key-plan.md for the rest of
// this round.
namespace shuzagram::mtproto::messages {

// bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long
//   perm_auth_key_id:long temp_session_id:long expires_at:int
//   = BindAuthKeyInner;
struct BindAuthKeyInner {
    static constexpr std::uint32_t kTypeId = 0x75a3f765;
    std::int64_t nonce = 0;
    std::int64_t temp_auth_key_id = 0;
    std::int64_t perm_auth_key_id = 0;
    std::int64_t temp_session_id = 0;
    std::int32_t expires_at = 0;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutLong(nonce);
        b.PutLong(temp_auth_key_id);
        b.PutLong(perm_auth_key_id);
        b.PutLong(temp_session_id);
        b.PutInt32(expires_at);
    }
    // Assumes ConsumeID(kTypeId) was already done by the caller (this
    // project's usual convention: the caller peeks the id to decide which
    // type to construct before decoding it).
    void DecodeBare(TLBuffer& b) {
        nonce = b.Long();
        temp_auth_key_id = b.Long();
        perm_auth_key_id = b.Long();
        temp_session_id = b.Long();
        expires_at = b.Int32();
    }
};

// auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long
//   expires_at:int encrypted_message:bytes = Bool;
//
// This connection's OWN auth_key_id (the temporary key being bound) is
// deliberately not a field here -- on the real wire it's implicit, taken
// from whichever auth_key decrypted this very RPC call. See
// mtproto::RpcContext in rpc_dispatch.hpp for how that's threaded through
// to the handler in this port.
struct AuthBindTempAuthKeyRequest {
    static constexpr std::uint32_t kTypeId = 0xcdd42a05;
    std::int64_t perm_auth_key_id = 0;
    std::int64_t nonce = 0;
    std::int32_t expires_at = 0;
    std::vector<std::uint8_t> encrypted_message;

    // Assumes ConsumeID(kTypeId) was already done by the caller.
    void DecodeBare(TLBuffer& b) {
        perm_auth_key_id = b.Long();
        nonce = b.Long();
        expires_at = b.Int32();
        encrypted_message = b.GetBytes();
    }
};

} // namespace shuzagram::mtproto::messages
