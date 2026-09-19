#pragma once

#include <cstdint>

#include "shuzagram/domain/user_errors.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// The "invoke wrapper" TL constructors real clients use to wrap almost
// every actual RPC call: invokeWithLayer#da9b0d0d layer:int query:!X = X,
// initConnection#c1cd5ea9 ... query:!X = X, invokeWithoutUpdates#bf9459b7
// query:!X = X, invokeAfterMsg#cb9f372d msg_id:long query:!X = X. None of
// them are business methods -- they carry a few metadata fields, then the
// REAL call's own encoding (constructor id + fields) follows immediately,
// with no length prefix (query:!X is "the rest of this object", not a TL
// bytes field).
//
// Before this was ported, every RPC handler this project registered
// (auth.sendCode, auth.signIn, ...) could only be reached by a test client
// that called it completely bare -- which is NOT what any real MTProto
// client does: TDesktop/Android/iOS/WebK all wrap at least their first
// call (usually every call) in invokeWithLayer(layer, initConnection(...,
// query)). Without unwrapping these, a real client's very first request
// would hit MtprotoSession::DispatchOne's registry lookup on
// InvokeWithLayerRequestTypeID, find nothing, and get METHOD_NOT_FOUND --
// so nothing built in every earlier round was actually reachable by a
// genuine client. See NOTES/invoke-wrappers-plan.md.
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kInvokeWithLayerTypeId = 0xda9b0d0d;
inline constexpr std::uint32_t kInvokeWithoutUpdatesTypeId = 0xbf9459b7;
inline constexpr std::uint32_t kInvokeAfterMsgTypeId = 0xcb9f372d;
inline constexpr std::uint32_t kInitConnectionTypeId = 0xc1cd5ea9;

// Repeatedly strips any of the four wrapper constructors above off the
// FRONT of `b` (a client can nest them, e.g.
// invokeWithLayer(initConnection(invokeWithoutUpdates(realCall)))),
// leaving exactly the real call's own id+fields in `b` for the ordinary
// dispatch path to handle as before. A buffer that starts with none of
// these ids is left untouched (the common case once unwrapped, or a
// legacy/bare call with no wrapper at all).
//
// initConnection's optional proxy (flags bit 0) and params (flags bit 1)
// fields are NOT decoded -- both are rare (proxy is for MTProto-proxy
// connections; params is an arbitrary JSON blob some clients attach) and
// correctly skipping either needs a decoder this project doesn't have yet
// (InputClientProxy, a generic JSONValue variant). A client that sets
// either flag gets domain::NotImplementedError rather than a silently
// corrupted parse of everything after it -- faithful-gap, not a silent
// truncation bug. initConnection's device/app metadata (api_id,
// device_model, ...) is likewise decoded and discarded, not yet persisted
// into store::AuthKeyClientInfo -- that wiring is a separate future round.
inline void UnwrapInvokeWrappers(TLBuffer& b) {
    for (;;) {
        const std::uint32_t id = b.PeekID();
        if (id == kInvokeWithLayerTypeId) {
            b.ConsumeID(id);
            (void)b.Int32(); // layer
            continue;
        }
        if (id == kInvokeWithoutUpdatesTypeId) {
            b.ConsumeID(id);
            continue;
        }
        if (id == kInvokeAfterMsgTypeId) {
            b.ConsumeID(id);
            (void)b.Long(); // msg_id
            continue;
        }
        if (id == kInitConnectionTypeId) {
            b.ConsumeID(id);
            const std::uint32_t flags = b.Uint32();
            (void)b.Int32();     // api_id
            (void)b.GetBytes();  // device_model
            (void)b.GetBytes();  // system_version
            (void)b.GetBytes();  // app_version
            (void)b.GetBytes();  // system_lang_code
            (void)b.GetBytes();  // lang_pack
            (void)b.GetBytes();  // lang_code
            if (flags & (1u << 0)) throw domain::NotImplementedError("initConnection with proxy");
            if (flags & (1u << 1)) throw domain::NotImplementedError("initConnection with params");
            continue;
        }
        return;
    }
}

} // namespace shuzagram::mtproto::messages
