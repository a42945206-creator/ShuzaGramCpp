#pragma once

#include "shuzagram/mtproto/tl_buffer.hpp"

// boolFalse#bc799737 = Bool; boolTrue#997275b5 = Bool;
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kBoolFalseTypeId = 0xbc799737;
inline constexpr std::uint32_t kBoolTrueTypeId = 0x997275b5;

inline void EncodeBool(TLBuffer& b, bool value) { b.PutID(value ? kBoolTrueTypeId : kBoolFalseTypeId); }

// account.updateStatus's offline:Bool field is the first thing in this port
// that needs to consume a bare Bool from the wire (everything before this
// only ever produced one).
inline bool DecodeBool(TLBuffer& b) {
    const std::uint32_t id = b.PeekID();
    if (id == kBoolTrueTypeId) {
        b.ConsumeID(id);
        return true;
    }
    if (id == kBoolFalseTypeId) {
        b.ConsumeID(id);
        return false;
    }
    throw UnexpectedIdError(id);
}

} // namespace shuzagram::mtproto::messages
