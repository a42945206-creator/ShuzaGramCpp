#pragma once

#include <string>

// Faithful port of the phone-identity functions in
// internal/domain/account.go. NormalizePhone/ValidPhone back onto
// libphonenumber (Google's C++ port, same underlying metadata as the Go
// nyaruka/phonenumbers library the original uses) instead of a hand-rolled
// parser.
namespace shuzagram::domain {

inline constexpr int kMinCollectiblePhoneLength = 7;
inline constexpr int kMaxCollectiblePhoneLength = 15;
inline constexpr const char* kOfficialSystemPhone = "42777";

// PhoneDigits removes presentation punctuation from a phone number. It is
// intentionally not an identity canonicalizer: callers that select accounts,
// issue codes, or persist users must use NormalizePhone and ValidPhone.
// Returns "" for anything containing a character it doesn't recognize as a
// digit, a single leading '+', or an accepted separator.
std::string PhoneDigits(const std::string& phone);

// NormalizePhone returns the one persisted login identity. Virtual +888
// identities are independent of the collectible-phone registry and accept
// 7-15 canonical digits. Ordinary international numbers use E.164 digits
// without the leading '+', parsed country-aware so a national trunk prefix
// is removed only where the numbering plan says it is a prefix. Returns ""
// if the input cannot be normalized to a persisted identity.
std::string NormalizePhone(const std::string& phone);

// ValidPhone reports whether phone is already in the persisted canonical
// form. Callers accepting user input normalize first, then validate, so
// equivalent international spellings converge before lookup, rate limiting,
// OTP delivery, and uniqueness checks.
bool ValidPhone(const std::string& phone);

} // namespace shuzagram::domain
