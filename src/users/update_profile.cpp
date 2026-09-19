#include "shuzagram/users/update_profile.hpp"

#include <cstddef>

#include "shuzagram/domain/user_errors.hpp"

namespace shuzagram::users {
namespace {

// Same ASCII-only trim already used for usernames in
// store/postgres/user_store.cpp's TrimUsername -- not a full
// unicode.IsSpace port, same deliberate scope as that one.
std::string TrimAsciiSpace(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) return "";
    const auto last = s.find_last_not_of(" \t\n\r\f\v");
    return s.substr(first, last - first + 1);
}

// utf8.RuneCountInString equivalent: counts codepoints, not bytes -- a
// continuation byte (10xxxxxx) never starts a new rune.
std::size_t Utf8RuneCount(const std::string& s) {
    std::size_t count = 0;
    for (unsigned char c : s) {
        if ((c & 0xC0) != 0x80) ++count;
    }
    return count;
}

constexpr std::size_t kMaxProfileNameRunes = 64;
constexpr std::size_t kMaxProfileAboutRunes = 70;
constexpr std::size_t kMaxProfileAboutRunesPremium = 140;

} // namespace

domain::User UpdateProfile(store::IUserStore& users, std::int64_t user_id,
                            const domain::UserProfileUpdate& update, std::int64_t now) {
    const auto self_opt = users.ByID(user_id);
    if (!self_opt.has_value()) throw domain::UserNotFoundError();
    const domain::User& self = *self_opt;

    const std::string first_name = update.has_first_name ? TrimAsciiSpace(update.first_name) : self.first_name;
    const std::string last_name = update.has_last_name ? TrimAsciiSpace(update.last_name) : self.last_name;
    const std::string about = update.has_about ? TrimAsciiSpace(update.about) : self.about;

    if (first_name.empty() || Utf8RuneCount(first_name) > kMaxProfileNameRunes ||
        Utf8RuneCount(last_name) > kMaxProfileNameRunes) {
        throw domain::FirstNameInvalidError();
    }
    const std::size_t about_limit = self.PremiumActiveAt(now) ? kMaxProfileAboutRunesPremium : kMaxProfileAboutRunes;
    if (Utf8RuneCount(about) > about_limit) {
        throw domain::AboutTooLongError();
    }

    if (first_name == self.first_name && last_name == self.last_name && about == self.about) {
        return self;
    }
    return users.UpdateProfile(user_id, first_name, last_name, about);
}

} // namespace shuzagram::users
