#include "shuzagram/users/username.hpp"

#include "shuzagram/domain/user_errors.hpp"

namespace shuzagram::users {
namespace {

constexpr std::size_t kMinUsernameLen = 5;
constexpr std::size_t kMaxUsernameLen = 32;

// loadSelf's ErrNotAuthorized (user_id == 0, or ByID comes back empty) maps
// to the same UserNotFoundError this port already uses for "no such user"
// everywhere else -- both are internalErr() defaults at the RPC boundary
// either way (see usernameErr in the real Go source), so there's no
// observable difference worth a separate exception type.
domain::User LoadSelf(store::IUserStore& users, std::int64_t user_id) {
    if (user_id == 0) throw domain::UserNotFoundError();
    auto self = users.ByID(user_id);
    if (!self.has_value()) throw domain::UserNotFoundError();
    return *self;
}

} // namespace

std::string NormalizeUsername(const std::string& username) {
    auto trim = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\n\r\f\v");
        if (first == std::string::npos) return std::string();
        const auto last = s.find_last_not_of(" \t\n\r\f\v");
        return s.substr(first, last - first + 1);
    };
    std::string s = trim(username);
    if (!s.empty() && s.front() == '@') s.erase(0, 1);
    return trim(s);
}

bool ValidUsername(const std::string& username) {
    if (username.size() < kMinUsernameLen || username.size() > kMaxUsernameLen) return false;
    for (std::size_t i = 0; i < username.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(username[i]);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) continue;
        if (c >= '0' && c <= '9') {
            if (i == 0) return false;
            continue;
        }
        if (c == '_') {
            if (i == 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

namespace {

// checkUsernameAvailable's fallback path (no usernameAvailabilityStore
// batch-checker equivalent ported): free, or already held by self_id.
bool CheckUsernameAvailable(store::IUserStore& users, std::int64_t self_id, const std::string& username) {
    const auto existing = users.ByUsername(username);
    return !existing.has_value() || existing->id == self_id;
}

} // namespace

bool CheckUsername(store::IUserStore& users, std::int64_t user_id, const std::string& username) {
    const auto self = LoadSelf(users, user_id);
    const std::string normalized = NormalizeUsername(username);
    if (!ValidUsername(normalized)) throw domain::UsernameInvalidError();
    return CheckUsernameAvailable(users, self.id, normalized);
}

domain::User UpdateUsername(store::IUserStore& users, std::int64_t user_id, const std::string& username) {
    const auto self = LoadSelf(users, user_id);
    const std::string normalized = NormalizeUsername(username);
    if (!normalized.empty()) {
        if (!ValidUsername(normalized)) throw domain::UsernameInvalidError();
        if (!CheckUsernameAvailable(users, self.id, normalized)) throw domain::UsernameOccupiedError();
    }
    if (self.username == normalized) return self;
    return users.UpdateUsername(self.id, normalized);
}

} // namespace shuzagram::users
