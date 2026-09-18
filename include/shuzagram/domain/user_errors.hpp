#pragma once

#include <stdexcept>
#include <string>

// Faithful port of the sentinel errors in internal/domain/user_errors.go
// that are reachable from the store slice ported so far. Go's
// errors.Is(err, domain.ErrX) sentinel-comparison idiom has no direct C++
// equivalent, so each sentinel becomes its own exception type instead
// (catchable individually, or as the common Error base) -- a deliberate
// translation, not an omission.
namespace shuzagram::domain {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& what) : std::runtime_error(what) {}
};

class UsernameOccupiedError : public Error {
public:
    UsernameOccupiedError() : Error("username occupied") {}
};

class UsernameInvalidError : public Error {
public:
    UsernameInvalidError() : Error("username invalid") {}
};

class UserNotFoundError : public Error {
public:
    UserNotFoundError() : Error("user not found") {}
};

class UserFrozenError : public Error {
public:
    UserFrozenError() : Error("user account frozen") {}
};

class BirthdayInvalidError : public Error {
public:
    BirthdayInvalidError() : Error("birthday invalid") {}
};

class PremiumRequiredError : public Error {
public:
    PremiumRequiredError() : Error("premium account required") {}
};

class PremiumBotUnsupportedError : public Error {
public:
    PremiumBotUnsupportedError() : Error("bot accounts cannot be premium") {}
};

class PeerModerationFlagsInvalidError : public Error {
public:
    PeerModerationFlagsInvalidError() : Error("peer moderation flags invalid") {}
};

} // namespace shuzagram::domain
