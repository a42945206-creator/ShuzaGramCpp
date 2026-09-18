#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "shuzagram/mtproto/tl_buffer.hpp"

// A handler receives the constructor id it was registered under (so one
// handler function can serve several related methods if useful), a
// TLBuffer positioned right after that id holding exactly that method's own
// fields, and the calling session's RpcContext. It returns the complete
// pre-encoded response object (with its own leading type id) --
// rpc_dispatch.cpp wraps it in rpc_result, the handler never needs to know
// it's inside one.
namespace shuzagram::mtproto {

// The per-call context every real MTProto RPC method needs and none of
// ping/msgs_ack/msg_container do: which auth_key decrypted this request,
// and which session (within that auth_key) it arrived on. Mirrors what
// Go's Router pulls out of ctx via AuthKeyIDFrom/SessionIDFrom
// (internal/rpc/router.go) -- deliberately just these two fields for now,
// since auth.bindTempAuthKey (the first handler that actually needs
// context) is the only caller so far; extend as more methods need more.
struct RpcContext {
    std::array<std::uint8_t, 8> auth_key_id{};
    std::int64_t session_id = 0;
};

using RpcHandler =
    std::function<std::vector<std::uint8_t>(std::uint32_t constructor_id, TLBuffer& body, const RpcContext& ctx)>;

// A minimal method registry. Real Telegram has thousands of RPC methods
// (the `tg` package in gotd/td); this project implements none of them as
// business logic -- see NOTES/rpc-dispatch-plan.md. What's here is the
// dispatch mechanism itself: MtprotoSession consults this registry for any
// constructor id it doesn't already handle as core protocol (ping,
// msgs_ack, msg_container), and returns a protocol-correct rpc_error for
// anything not registered, instead of silently dropping the request or
// crashing.
class RpcHandlerRegistry {
public:
    void Register(std::uint32_t constructor_id, RpcHandler handler) { handlers_[constructor_id] = std::move(handler); }

    [[nodiscard]] const RpcHandler* Find(std::uint32_t constructor_id) const {
        const auto it = handlers_.find(constructor_id);
        return it == handlers_.end() ? nullptr : &it->second;
    }

private:
    std::unordered_map<std::uint32_t, RpcHandler> handlers_;
};

} // namespace shuzagram::mtproto
