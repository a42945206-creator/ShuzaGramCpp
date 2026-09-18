#include "shuzagram/domain/phone.hpp"

#include <cctype>

#include <phonenumbers/phonenumber.pb.h>
#include <phonenumbers/phonenumberutil.h>

namespace shuzagram::domain {

std::string PhoneDigits(const std::string& phone) {
    std::string out;
    out.reserve(phone.size());
    bool seen_digit = false;
    bool seen_plus = false;
    for (unsigned char c : phone) {
        if (c >= '0' && c <= '9') {
            out.push_back(static_cast<char>(c));
            seen_digit = true;
        } else if (c == '+') {
            if (seen_plus || seen_digit) return "";
            seen_plus = true;
        } else if (std::isspace(c) || c == '-' || c == '(' || c == ')' || c == '.' || c == '/') {
            // Presentation separators accepted by official clients and contact UIs.
        } else {
            return "";
        }
    }
    return out;
}

std::string NormalizePhone(const std::string& phone) {
    const std::string digits = PhoneDigits(phone);
    if (digits.empty()) return "";

    // Every syntactically valid +888 virtual number is an independent login
    // identity; minting or owning the same collectible-phone value is not a
    // prerequisite. users.phone therefore takes lookup precedence over the
    // optional collectible alias registry.
    if (digits.size() >= static_cast<std::size_t>(kMinCollectiblePhoneLength) &&
        digits.size() <= static_cast<std::size_t>(kMaxCollectiblePhoneLength) &&
        digits.rfind("888", 0) == 0) {
        return digits;
    }

    // 42777 is the reserved, non-login phone of the built-in service
    // identity. It predates the ordinary E.164 user invariant and remains
    // resolvable only so auth can reject it as a system account instead of
    // treating it as free.
    if (digits == kOfficialSystemPhone) return digits;

    auto* util = i18n::phonenumbers::PhoneNumberUtil::GetInstance();
    i18n::phonenumbers::PhoneNumber number;
    const auto error = util->Parse("+" + digits, "ZZ", &number); // ZZ == UNKNOWN_REGION
    if (error != i18n::phonenumbers::PhoneNumberUtil::NO_PARSING_ERROR ||
        !util->IsPossibleNumber(number)) {
        return "";
    }

    std::string formatted;
    util->Format(number, i18n::phonenumbers::PhoneNumberUtil::E164, &formatted);
    if (!formatted.empty() && formatted.front() == '+') formatted.erase(0, 1);
    if (formatted.empty() || formatted.size() > 15) return "";
    return formatted;
}

bool ValidPhone(const std::string& phone) {
    const std::string canonical = NormalizePhone(phone);
    return !canonical.empty() && canonical == phone;
}

} // namespace shuzagram::domain
