#pragma once

#include <cstdint>
#include <string>

// Minimal slice of the message domain needed by domain::User
// (ContactNoteEntities). The full message/formatting domain (message.go,
// ~large) is ported separately; only the entity shape used here is included.
namespace shuzagram::domain {

enum class MessageEntityType {
    Bold,
    Italic,
    Underline,
    Strike,
    Code,
    Pre,
    TextURL,
    MentionName,
    Spoiler,
    Blockquote,
    CustomEmoji,
    Mention,
    Hashtag,
    Cashtag,
    BotCommand,
    URL,
    Email,
    Phone,
};

struct MessageEntity {
    MessageEntityType type{};
    int offset = 0;
    int length = 0;
    std::string url;          // text_url only
    std::int64_t user_id = 0; // mention_name only
    std::string language;     // pre only
    std::int64_t document_id = 0; // custom_emoji only
    bool collapsed = false;   // blockquote only

    friend bool operator==(const MessageEntity&, const MessageEntity&) = default;
};

} // namespace shuzagram::domain
