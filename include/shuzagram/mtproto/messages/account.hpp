#pragma once

#include <cstdint>

#include "shuzagram/mtproto/messages/bool.hpp"
#include "shuzagram/mtproto/tl_buffer.hpp"

// account.updateStatus#6628562c offline:Bool = Bool;
//
// Constructor id copied from gotd/td (github.com/iamxvbaba/td@v1.3.3,
// tg/tl_account_update_status_gen.go), same as every other messages/ header
// in this project.
namespace shuzagram::mtproto::messages {

struct AccountUpdateStatusRequest {
    static constexpr std::uint32_t kTypeId = 0x6628562c;
    bool offline = false;

    void DecodeBare(TLBuffer& b) { offline = DecodeBool(b); }
};

} // namespace shuzagram::mtproto::messages
