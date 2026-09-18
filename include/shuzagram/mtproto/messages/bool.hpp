#pragma once

#include "shuzagram/mtproto/tl_buffer.hpp"

// boolFalse#bc799737 = Bool; boolTrue#997275b5 = Bool;
//
// Just the two type ids and a one-line encoder -- not a generic Bool
// decode/box type, since nothing in this port needs to consume a bare Bool
// from the wire yet (only auth.bindTempAuthKey's response produces one).
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kBoolFalseTypeId = 0xbc799737;
inline constexpr std::uint32_t kBoolTrueTypeId = 0x997275b5;

inline void EncodeBool(TLBuffer& b, bool value) { b.PutID(value ? kBoolTrueTypeId : kBoolFalseTypeId); }

} // namespace shuzagram::mtproto::messages
