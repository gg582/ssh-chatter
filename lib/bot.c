#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "headers/bot.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "headers/client.h"
#include "headers/host.h"
#include "headers/humanized/humanized.h"

#define CHAT_BOT_ENV_PATH "/etc/ssh-chatter/chatter.env"
#define CHAT_BOT_DEFAULT_NAME "chatgpt"
#define CHAT_BOT_DEFAULT_MODEL "gpt-4o-mini"
#define CHAT_BOT_QUEUE_LENGTH 16U
#define CHAT_BOT_PROMPT_DEFAULT "You are a friendly assistant that participates in a terminal chat room."
#define CHAT_BOT_HTTP_TIMEOUT 20L
#define CHAT_BOT_SHORT_MEMORY 32U
#define CHAT_BOT_LONG_MEMORY 8U
#define CHAT_BOT_LONG_ENTRY_LEN 160U
#define CHAT_BOT_MEMORY_ENV_PATH "CHAT_BOT_MEMORY_FILE"
#define CHAT_BOT_MEMORY_DEFAULT "chat_bot_memory.dat"
#define CHAT_BOT_MEMORY_MAGIC 0x43424D45U
#define CHAT_BOT_MEMORY_VERSION 1U

typedef struct chat_bot_message {
  char username[SSH_CHATTER_USERNAME_LEN];
  char content[SSH_CHATTER_MESSAGE_LIMIT];
  bool from_bot;
} chat_bot_message_t;

typedef struct chat_bot_memory_snapshot {
  chat_bot_message_t short_messages[CHAT_BOT_SHORT_MEMORY];
  size_t short_count;
  char long_entries[CHAT_BOT_LONG_MEMORY][CHAT_BOT_LONG_ENTRY_LEN];
  size_t long_count;
} chat_bot_memory_snapshot_t;

typedef struct chat_bot_memory_header {
  uint32_t magic;
  uint32_t version;
  uint32_t short_count;
  uint32_t long_count;
} chat_bot_memory_header_t;

typedef struct chat_bot_memory_short_entry {
  char username[SSH_CHATTER_USERNAME_LEN];
  char content[SSH_CHATTER_MESSAGE_LIMIT];
  uint8_t from_bot;
  uint8_t reserved[3];
} chat_bot_memory_short_entry_t;

typedef struct chat_bot_memory_long_entry {
  char content[CHAT_BOT_LONG_ENTRY_LEN];
} chat_bot_memory_long_entry_t;

struct chat_bot {
  struct host *host;
  client_manager_t *manager;
  client_connection_t connection;
  pthread_t thread;
  bool thread_started;
  bool shutting_down;
  bool enabled;
  bool registered;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  chat_bot_message_t queue[CHAT_BOT_QUEUE_LENGTH];
  size_t queue_start;
  size_t queue_count;
  char api_key[512];
  char system_prompt[1024];
  char model[64];
  char name[SSH_CHATTER_USERNAME_LEN];
  char name_lower[SSH_CHATTER_USERNAME_LEN];
  chat_bot_message_t short_memory[CHAT_BOT_SHORT_MEMORY];
  size_t short_memory_start;
  size_t short_memory_count;
  char long_memory[CHAT_BOT_LONG_MEMORY][CHAT_BOT_LONG_ENTRY_LEN];
  size_t long_memory_start;
  size_t long_memory_count;
  char memory_file_path[PATH_MAX];
  bool has_captcha_hint;
  char captcha_question[256];
  char captcha_answer[64];
  struct timespec captcha_hint_time;
};

typedef struct chat_bot_buffer_state {
  char *data;
  size_t size;
} chat_bot_buffer_state_t;

static void chat_bot_save_memory_locked(chat_bot_t *bot);

static void chat_bot_init_queue(chat_bot_t *bot) {
  bot->queue_start = 0U;
  bot->queue_count = 0U;
  for (size_t idx = 0U; idx < CHAT_BOT_QUEUE_LENGTH; ++idx) {
    bot->queue[idx].username[0] = '\0';
    bot->queue[idx].content[0] = '\0';
    bot->queue[idx].from_bot = false;
  }
}

// Reset both short-term and long-term memory buffers so the bot starts from a clean slate.
static void chat_bot_reset_memory(chat_bot_t *bot) {
  if (bot == NULL) {
    return;
  }

  bot->short_memory_start = 0U;
  bot->short_memory_count = 0U;
  for (size_t idx = 0U; idx < CHAT_BOT_SHORT_MEMORY; ++idx) {
    bot->short_memory[idx].username[0] = '\0';
    bot->short_memory[idx].content[0] = '\0';
    bot->short_memory[idx].from_bot = false;
  }

  bot->long_memory_start = 0U;
  bot->long_memory_count = 0U;
  for (size_t idx = 0U; idx < CHAT_BOT_LONG_MEMORY; ++idx) {
    bot->long_memory[idx][0] = '\0';
  }
}

// Keep a lowercase copy of the bot name for quick case-insensitive comparisons.
static void chat_bot_update_name_lower(chat_bot_t *bot) {
  if (bot == NULL) {
    return;
  }

  size_t idx = 0U;
  for (; idx + 1U < sizeof(bot->name_lower) && bot->name[idx] != '\0'; ++idx) {
    bot->name_lower[idx] = (char)tolower((unsigned char)bot->name[idx]);
  }
  if (idx < sizeof(bot->name_lower)) {
    bot->name_lower[idx] = '\0';
  }
}

static size_t chat_bot_strnlen(const char *text, size_t max_len) {
  if (text == NULL) {
    return 0U;
  }
  size_t len = 0U;
  while (len < max_len && text[len] != '\0') {
    ++len;
  }
  return len;
}

static void chat_bot_trim(char *text) {
  if (text == NULL) {
    return;
  }

  char *begin = text;
  while (*begin != '\0' && isspace((unsigned char)*begin)) {
    ++begin;
  }
  if (begin != text) {
    memmove(text, begin, strlen(begin) + 1U);
  }

  size_t len = strlen(text);
  while (len > 0U && isspace((unsigned char)text[len - 1U])) {
    text[len - 1U] = '\0';
    --len;
  }
}

// Decide whether a user message deserves to be promoted into long-term memory.
static bool chat_bot_memory_should_promote(const chat_bot_t *bot, const chat_bot_message_t *message) {
  if (bot == NULL || message == NULL) {
    return false;
  }
  if (message->from_bot) {
    return false;
  }

  char lowered[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(lowered, sizeof(lowered), "%s", message->content);
  for (size_t idx = 0U; lowered[idx] != '\0'; ++idx) {
    lowered[idx] = (char)tolower((unsigned char)lowered[idx]);
  }

  if (bot->name_lower[0] != '\0' && strstr(lowered, bot->name_lower) != NULL) {
    return true;
  }
  if (strstr(lowered, "remember") != NULL) {
    return true;
  }
  if (strstr(lowered, "note") != NULL) {
    return true;
  }

  return false;
}

// Store a condensed note derived from the message into the rolling long-term memory buffer.
static void chat_bot_promote_long_memory_locked(chat_bot_t *bot, const chat_bot_message_t *message) {
  if (bot == NULL || message == NULL) {
    return;
  }

  if (!chat_bot_memory_should_promote(bot, message)) {
    return;
  }

  char snippet[CHAT_BOT_LONG_ENTRY_LEN];
  snprintf(snippet, sizeof(snippet), "%s: %.120s", message->username, message->content);
  chat_bot_trim(snippet);

  for (size_t idx = 0U; idx < bot->long_memory_count; ++idx) {
    size_t index = (bot->long_memory_start + idx) % CHAT_BOT_LONG_MEMORY;
    if (strcasecmp(bot->long_memory[index], snippet) == 0) {
      return;
    }
  }

  size_t insert_index;
  if (bot->long_memory_count < CHAT_BOT_LONG_MEMORY) {
    insert_index = (bot->long_memory_start + bot->long_memory_count) % CHAT_BOT_LONG_MEMORY;
    ++bot->long_memory_count;
  } else {
    insert_index = bot->long_memory_start;
    bot->long_memory_start = (bot->long_memory_start + 1U) % CHAT_BOT_LONG_MEMORY;
  }

  snprintf(bot->long_memory[insert_index], sizeof(bot->long_memory[insert_index]), "%s", snippet);
}

// Append the message to the short-term memory window and update long-term notes when needed.
static void chat_bot_record_memory_locked(chat_bot_t *bot, const chat_bot_message_t *message) {
  if (bot == NULL || message == NULL) {
    return;
  }

  size_t insert_index;
  if (bot->short_memory_count < CHAT_BOT_SHORT_MEMORY) {
    insert_index = (bot->short_memory_start + bot->short_memory_count) % CHAT_BOT_SHORT_MEMORY;
    ++bot->short_memory_count;
  } else {
    insert_index = bot->short_memory_start;
    bot->short_memory_start = (bot->short_memory_start + 1U) % CHAT_BOT_SHORT_MEMORY;
  }

  snprintf(bot->short_memory[insert_index].username, sizeof(bot->short_memory[insert_index].username), "%s",
           message->username);
  snprintf(bot->short_memory[insert_index].content, sizeof(bot->short_memory[insert_index].content), "%s",
           message->content);
  bot->short_memory[insert_index].from_bot = message->from_bot;

  chat_bot_promote_long_memory_locked(bot, message);
  chat_bot_save_memory_locked(bot);
}

// Copy the current short-term and long-term memory into a snapshot used for request assembly.
static void chat_bot_snapshot_memory(chat_bot_t *bot, chat_bot_memory_snapshot_t *snapshot) {
  if (bot == NULL || snapshot == NULL) {
    return;
  }

  snapshot->short_count = 0U;
  snapshot->long_count = 0U;

  for (size_t idx = 0U; idx < bot->short_memory_count && idx < CHAT_BOT_SHORT_MEMORY; ++idx) {
    size_t index = (bot->short_memory_start + idx) % CHAT_BOT_SHORT_MEMORY;
    snapshot->short_messages[idx] = bot->short_memory[index];
    ++snapshot->short_count;
  }

  for (size_t idx = 0U; idx < bot->long_memory_count && idx < CHAT_BOT_LONG_MEMORY; ++idx) {
    size_t index = (bot->long_memory_start + idx) % CHAT_BOT_LONG_MEMORY;
    snprintf(snapshot->long_entries[idx], sizeof(snapshot->long_entries[idx]), "%s", bot->long_memory[index]);
    ++snapshot->long_count;
  }
}

static void chat_bot_resolve_memory_path(chat_bot_t *bot) {
  if (bot == NULL) {
    return;
  }

  const char *path = getenv(CHAT_BOT_MEMORY_ENV_PATH);
  if (path == NULL || path[0] == '\0') {
    path = CHAT_BOT_MEMORY_DEFAULT;
  }

  snprintf(bot->memory_file_path, sizeof(bot->memory_file_path), "%s", path);
}

static bool chat_bot_load_memory(chat_bot_t *bot) {
  if (bot == NULL || bot->memory_file_path[0] == '\0') {
    return false;
  }

  FILE *fp = fopen(bot->memory_file_path, "rb");
  if (fp == NULL) {
    return false;
  }

  chat_bot_memory_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return false;
  }

  if (header.magic != CHAT_BOT_MEMORY_MAGIC || header.version != CHAT_BOT_MEMORY_VERSION) {
    fclose(fp);
    return false;
  }

  chat_bot_reset_memory(bot);

  for (uint32_t idx = 0U; idx < header.short_count; ++idx) {
    chat_bot_memory_short_entry_t entry = {0};
    if (fread(&entry, sizeof(entry), 1U, fp) != 1U) {
      fclose(fp);
      chat_bot_reset_memory(bot);
      return false;
    }
    if (bot->short_memory_count >= CHAT_BOT_SHORT_MEMORY) {
      continue;
    }
    chat_bot_message_t *slot = &bot->short_memory[bot->short_memory_count++];
    snprintf(slot->username, sizeof(slot->username), "%s", entry.username);
    snprintf(slot->content, sizeof(slot->content), "%s", entry.content);
    slot->from_bot = entry.from_bot != 0U;
  }
  bot->short_memory_start = 0U;

  for (uint32_t idx = 0U; idx < header.long_count; ++idx) {
    chat_bot_memory_long_entry_t entry = {0};
    if (fread(&entry, sizeof(entry), 1U, fp) != 1U) {
      fclose(fp);
      chat_bot_reset_memory(bot);
      return false;
    }
    if (bot->long_memory_count >= CHAT_BOT_LONG_MEMORY) {
      continue;
    }
    snprintf(bot->long_memory[bot->long_memory_count], sizeof(bot->long_memory[bot->long_memory_count]), "%s",
             entry.content);
    ++bot->long_memory_count;
  }
  bot->long_memory_start = 0U;

  fclose(fp);
  return true;
}

static void chat_bot_save_memory_locked(chat_bot_t *bot) {
  if (bot == NULL || bot->memory_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", bot->memory_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    return;
  }

  chat_bot_memory_snapshot_t snapshot = {0};
  chat_bot_snapshot_memory(bot, &snapshot);

  chat_bot_memory_header_t header = {0};
  header.magic = CHAT_BOT_MEMORY_MAGIC;
  header.version = CHAT_BOT_MEMORY_VERSION;
  header.short_count = (uint32_t)snapshot.short_count;
  header.long_count = (uint32_t)snapshot.long_count;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  for (size_t idx = 0U; success && idx < snapshot.short_count; ++idx) {
    chat_bot_memory_short_entry_t entry = {0};
    const chat_bot_message_t *message = &snapshot.short_messages[idx];
    snprintf(entry.username, sizeof(entry.username), "%s", message->username);
    snprintf(entry.content, sizeof(entry.content), "%s", message->content);
    entry.from_bot = message->from_bot ? 1U : 0U;
    if (fwrite(&entry, sizeof(entry), 1U, fp) != 1U) {
      success = false;
    }
  }

  for (size_t idx = 0U; success && idx < snapshot.long_count; ++idx) {
    chat_bot_memory_long_entry_t entry = {0};
    snprintf(entry.content, sizeof(entry.content), "%s", snapshot.long_entries[idx]);
    if (fwrite(&entry, sizeof(entry), 1U, fp) != 1U) {
      success = false;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
  }
  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
    }
  }

  if (fclose(fp) != 0) {
    success = false;
  }

  if (success) {
    if (rename(temp_path, bot->memory_file_path) != 0) {
      unlink(temp_path);
    }
  } else {
    unlink(temp_path);
  }
}

// Seed the memory buffers with the most recent chat log entries so the bot knows the room context.
static void chat_bot_seed_history(chat_bot_t *bot) {
  if (bot == NULL || bot->host == NULL) {
    return;
  }

  chat_bot_message_t buffer[CHAT_BOT_SHORT_MEMORY];
  size_t buffer_count = 0U;

  pthread_mutex_lock(&bot->host->lock);
  size_t history_count = bot->host->history_count;
  for (size_t idx = 0U; idx < history_count && buffer_count < CHAT_BOT_SHORT_MEMORY; ++idx) {
    size_t history_index = (bot->host->history_start + history_count - idx - 1U) % SSH_CHATTER_HISTORY_LIMIT;
    const chat_history_entry_t *entry = &bot->host->history[history_index];
    if (!entry->is_user_message) {
      continue;
    }
    snprintf(buffer[buffer_count].username, sizeof(buffer[buffer_count].username), "%s", entry->username);
    snprintf(buffer[buffer_count].content, sizeof(buffer[buffer_count].content), "%s", entry->message);
    buffer[buffer_count].from_bot = strncmp(entry->username, bot->name, sizeof(entry->username)) == 0;
    ++buffer_count;
  }
  pthread_mutex_unlock(&bot->host->lock);

  if (buffer_count == 0U) {
    return;
  }

  pthread_mutex_lock(&bot->lock);
  for (size_t idx = 0U; idx < buffer_count; ++idx) {
    size_t reverse_index = buffer_count - idx - 1U;
    chat_bot_record_memory_locked(bot, &buffer[reverse_index]);
  }
  pthread_mutex_unlock(&bot->lock);
}

// Blend the configured system prompt with long-term notes so the API sees persistent state.
static void chat_bot_build_system_context(const chat_bot_t *bot, const chat_bot_memory_snapshot_t *snapshot, char *output,
                                          size_t length) {
  if (bot == NULL || output == NULL || length == 0U) {
    return;
  }

  if (snapshot == NULL || snapshot->long_count == 0U) {
    snprintf(output, length, "%s", bot->system_prompt);
    return;
  }

  char notes[CHAT_BOT_LONG_MEMORY * (CHAT_BOT_LONG_ENTRY_LEN + 4U)];
  size_t offset = 0U;
  notes[0] = '\0';

  for (size_t idx = 0U; idx < snapshot->long_count; ++idx) {
    int written = snprintf(notes + offset, sizeof(notes) - offset, "- %s\n", snapshot->long_entries[idx]);
    if (written < 0) {
      break;
    }
    size_t size_written = (size_t)written;
    if (size_written >= sizeof(notes) - offset) {
      offset = sizeof(notes) - 1U;
      break;
    }
    offset += size_written;
  }

  if (offset == 0U) {
    snprintf(output, length, "%s", bot->system_prompt);
    return;
  }

  output[0] = '\0';
  if (length == 0U) {
    return;
  }

  size_t capacity = length - 1U;
  size_t prompt_len = chat_bot_strnlen(bot->system_prompt, capacity);
  memcpy(output, bot->system_prompt, prompt_len);
  size_t written = prompt_len;
  output[written] = '\0';

  const char *header = "\n\nPersistent observations:\n";
  size_t header_len = strlen(header);
  if (header_len > capacity - written) {
    header_len = capacity > written ? capacity - written : 0U;
  }
  memcpy(output + written, header, header_len);
  written += header_len;
  output[written] = '\0';

  size_t available = capacity > written ? capacity - written : 0U;
  size_t notes_len = chat_bot_strnlen(notes, available);
  memcpy(output + written, notes, notes_len);
  written += notes_len;
  output[written] = '\0';
}

static void chat_bot_strip_quotes(char *text) {
  if (text == NULL) {
    return;
  }
  size_t len = strlen(text);
  if (len >= 2U && ((text[0] == '"' && text[len - 1U] == '"') || (text[0] == '\'' && text[len - 1U] == '\''))) {
    text[len - 1U] = '\0';
    memmove(text, text + 1, len - 1U);
  }
}

static int chat_bot_hex_value(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

static void chat_bot_append_utf8(unsigned int codepoint, char *output, size_t *written, size_t capacity) {
  if (output == NULL || written == NULL || capacity == 0U) {
    return;
  }

  if (*written >= capacity - 1U) {
    return;
  }

  if (codepoint <= 0x7FU) {
    output[(*written)++] = (char)codepoint;
  } else if (codepoint <= 0x7FFU) {
    if (*written + 2U >= capacity) {
      return;
    }
    output[(*written)++] = (char)(0xC0U | ((codepoint >> 6U) & 0x1FU));
    output[(*written)++] = (char)(0x80U | (codepoint & 0x3FU));
  } else if (codepoint <= 0xFFFFU) {
    if (*written + 3U >= capacity) {
      return;
    }
    output[(*written)++] = (char)(0xE0U | ((codepoint >> 12U) & 0x0FU));
    output[(*written)++] = (char)(0x80U | ((codepoint >> 6U) & 0x3FU));
    output[(*written)++] = (char)(0x80U | (codepoint & 0x3FU));
  } else if (codepoint <= 0x10FFFFU) {
    if (*written + 4U >= capacity) {
      return;
    }
    output[(*written)++] = (char)(0xF0U | ((codepoint >> 18U) & 0x07U));
    output[(*written)++] = (char)(0x80U | ((codepoint >> 12U) & 0x3FU));
    output[(*written)++] = (char)(0x80U | ((codepoint >> 6U) & 0x3FU));
    output[(*written)++] = (char)(0x80U | (codepoint & 0x3FU));
  }
}

static void chat_bot_decode_unicode_sequence(const char **cursor, const char *end, char *output, size_t *written,
                                             size_t capacity) {
  if (cursor == NULL || *cursor == NULL || end == NULL || output == NULL || written == NULL) {
    return;
  }

  if (**cursor == 'u' || **cursor == 'U') {
    if (*cursor + 1 >= end) {
      return;
    }
    ++(*cursor);
  }

  if (end - *cursor < 4) {
    return;
  }

  unsigned int codepoint = 0U;
  for (int idx = 0; idx < 4; ++idx) {
    int value = chat_bot_hex_value((*cursor)[idx]);
    if (value < 0) {
      return;
    }
    codepoint = (codepoint << 4U) | (unsigned int)value;
  }
  *cursor += 4;

  if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
    if (end - *cursor < 6) {
      return;
    }
    if ((*cursor)[0] == '\\' && (*cursor)[1] == 'u') {
      const char *low_start = *cursor + 2;
      unsigned int low_codepoint = 0U;
      for (int idx = 0; idx < 4; ++idx) {
        int value = chat_bot_hex_value(low_start[idx]);
        if (value < 0) {
          return;
        }
        low_codepoint = (low_codepoint << 4U) | (unsigned int)value;
      }
      if (low_codepoint >= 0xDC00U && low_codepoint <= 0xDFFFU) {
        codepoint = 0x10000U + (((codepoint - 0xD800U) << 10U) | (low_codepoint - 0xDC00U));
        *cursor += 6;
      }
    }
  }

  chat_bot_append_utf8(codepoint, output, written, capacity);
}

static bool chat_bot_extract_reply(const char *json, char *output, size_t capacity) {
  if (json == NULL || output == NULL || capacity == 0U) {
    return false;
  }

  const char *choices = strstr(json, "\"choices\"");
  if (choices == NULL) {
    return false;
  }
  const char *content = strstr(choices, "\"content\"");
  if (content == NULL) {
    return false;
  }
  const char *start = strchr(content, '"');
  if (start == NULL) {
    return false;
  }
  ++start;

  const char *end = json + strlen(json);
  bool escape = false;
  size_t written = 0U;
  for (const char *cursor = start; cursor < end; ++cursor) {
    char ch = *cursor;
    if (escape) {
      switch (ch) {
        case '\\':
        case '\"':
        case '/':
          if (written + 1U < capacity) {
            output[written++] = ch;
          }
          break;
        case 'n':
          if (written + 1U < capacity) {
            output[written++] = '\n';
          }
          break;
        case 'r':
          break;
        case 't':
          if (written + 1U < capacity) {
            output[written++] = '\t';
          }
          break;
        case 'u': {
          chat_bot_decode_unicode_sequence(&cursor, end, output, &written, capacity);
          --cursor;
          break;
        }
        default:
          if (written + 1U < capacity) {
            output[written++] = ch;
          }
          break;
      }
      escape = false;
      continue;
    }

    if (ch == '\\') {
      escape = true;
      continue;
    }
    if (ch == '"') {
      break;
    }

    if (written + 1U >= capacity) {
      break;
    }
    output[written++] = ch;
  }

  output[written < capacity ? written : capacity - 1U] = '\0';
  return written > 0U;
}

static bool chat_bot_json_escape(const char *input, char *output, size_t capacity) {
  if (output == NULL || capacity == 0U) {
    return false;
  }

  size_t written = 0U;
  if (input == NULL) {
    output[0] = '\0';
    return true;
  }

  for (const unsigned char *cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
    const char *replacement = NULL;
    char buffer[8];
    switch (*cursor) {
      case '\"':
        replacement = "\\\"";
        break;
      case '\\':
        replacement = "\\\\";
        break;
      case '\n':
        replacement = "\\n";
        break;
      case '\r':
        replacement = "\\r";
        break;
      case '\t':
        replacement = "\\t";
        break;
      default:
        if (*cursor < 0x20U) {
          snprintf(buffer, sizeof(buffer), "\\u%04X", *cursor);
          replacement = buffer;
        }
        break;
    }

    if (replacement != NULL) {
      size_t len = strlen(replacement);
      if (written + len >= capacity) {
        output[written] = '\0';
        return false;
      }
      memcpy(output + written, replacement, len);
      written += len;
    } else {
      if (written + 1U >= capacity) {
        output[written] = '\0';
        return false;
      }
      output[written++] = (char)*cursor;
    }
  }

  output[written] = '\0';
  return true;
}

static void chat_bot_trim_message(char *message) {
  if (message == NULL) {
    return;
  }
  chat_bot_trim(message);
  size_t len = strlen(message);
  while (len > 0U) {
    if (message[len - 1U] == '\n' || message[len - 1U] == '\r') {
      message[len - 1U] = '\0';
      --len;
      continue;
    }
    break;
  }
}

static void chat_bot_load_env(chat_bot_t *bot) {
  FILE *file = fopen(CHAT_BOT_ENV_PATH, "r");
  if (file == NULL) {
    return;
  }

  char line[2048];
  while (fgets(line, sizeof(line), file) != NULL) {
    chat_bot_trim(line);
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }
    if (strncmp(line, "export ", 7) == 0) {
      memmove(line, line + 7, strlen(line + 7) + 1U);
      chat_bot_trim(line);
    }
    char *equals = strchr(line, '=');
    if (equals == NULL) {
      continue;
    }
    *equals = '\0';
    char *key = line;
    char *value = equals + 1;
    chat_bot_trim(key);
    chat_bot_trim(value);
    chat_bot_strip_quotes(value);

    if (strcmp(key, "OPENAI_API_KEY") == 0) {
      snprintf(bot->api_key, sizeof(bot->api_key), "%s", value);
    } else if (strcmp(key, "CHAT_BOT_PROMPT") == 0) {
      snprintf(bot->system_prompt, sizeof(bot->system_prompt), "%s", value);
    } else if (strcmp(key, "CHAT_BOT_NAME") == 0) {
      if (value[0] != '\0') {
        snprintf(bot->name, sizeof(bot->name), "%s", value);
      }
    } else if (strcmp(key, "CHAT_BOT_MODEL") == 0) {
      if (value[0] != '\0') {
        snprintf(bot->model, sizeof(bot->model), "%s", value);
      }
    }
  }

  fclose(file);
}

static pthread_once_t g_chat_bot_curl_once = PTHREAD_ONCE_INIT;

static void chat_bot_init_curl(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t chat_bot_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t total = size * nmemb;
  chat_bot_buffer_state_t *state = (chat_bot_buffer_state_t *)userp;

  if (state->data == NULL) {
    state->data = malloc(total + 1U);
    if (state->data == NULL) {
      return 0U;
    }
    memcpy(state->data, contents, total);
    state->data[total] = '\0';
    state->size = total;
    return total;
  }

  char *resized = realloc(state->data, state->size + total + 1U);
  if (resized == NULL) {
    return 0U;
  }
  state->data = resized;
  memcpy(state->data + state->size, contents, total);
  state->size += total;
  state->data[state->size] = '\0';
  return total;
}

static bool chat_bot_generate_reply(chat_bot_t *bot, const chat_bot_message_t *message,
                                    const chat_bot_memory_snapshot_t *snapshot, char *response,
                                    size_t response_length) {
  if (bot == NULL || message == NULL || response == NULL || response_length == 0U) {
    return false;
  }
  if (!bot->enabled) {
    return false;
  }

  pthread_once(&g_chat_bot_curl_once, chat_bot_init_curl);

  CURL *handle = curl_easy_init();
  if (handle == NULL) {
    humanized_log_error("chat-bot", "failed to create curl handle", ENOMEM);
    return false;
  }

  char system_context[2048];
  chat_bot_build_system_context(bot, snapshot, system_context, sizeof(system_context));

  char escaped_prompt[4096];
  if (!chat_bot_json_escape(system_context, escaped_prompt, sizeof(escaped_prompt))) {
    curl_easy_cleanup(handle);
    return false;
  }

  char payload[65536];
  size_t offset = 0U;
  int written = snprintf(payload, sizeof(payload),
                         "{\"model\":\"%s\",\"messages\":[{\"role\":\"system\",\"content\":\"%s\"}", bot->model,
                         escaped_prompt);
  if (written < 0 || (size_t)written >= sizeof(payload)) {
    curl_easy_cleanup(handle);
    return false;
  }
  offset = (size_t)written;

  if (snapshot != NULL) {
    for (size_t idx = 0U; idx < snapshot->short_count; ++idx) {
      const chat_bot_message_t *historical = &snapshot->short_messages[idx];
      char message_text[SSH_CHATTER_MESSAGE_LIMIT + SSH_CHATTER_USERNAME_LEN + 8U];
      snprintf(message_text, sizeof(message_text), "%s: %s", historical->username, historical->content);
      char escaped_message[4096];
      if (!chat_bot_json_escape(message_text, escaped_message, sizeof(escaped_message))) {
        curl_easy_cleanup(handle);
        return false;
      }
      const char *role = historical->from_bot ? "assistant" : "user";
      written = snprintf(payload + offset, sizeof(payload) - offset, ",{\"role\":\"%s\",\"content\":\"%s\"}", role,
                         escaped_message);
      if (written < 0 || (size_t)written >= sizeof(payload) - offset) {
        curl_easy_cleanup(handle);
        return false;
      }
      offset += (size_t)written;
    }
  }

  char user_payload[SSH_CHATTER_MESSAGE_LIMIT + SSH_CHATTER_USERNAME_LEN + 8U];
  snprintf(user_payload, sizeof(user_payload), "%s: %s", message->username, message->content);
  char escaped_message[4096];
  if (!chat_bot_json_escape(user_payload, escaped_message, sizeof(escaped_message))) {
    curl_easy_cleanup(handle);
    return false;
  }

  written = snprintf(payload + offset, sizeof(payload) - offset, ",{\"role\":\"user\",\"content\":\"%s\"}]}",
                     escaped_message);
  if (written < 0 || (size_t)written >= sizeof(payload) - offset) {
    curl_easy_cleanup(handle);
    return false;
  }

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char auth_header[640];
  snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", bot->api_key);
  headers = curl_slist_append(headers, auth_header);

  curl_easy_setopt(handle, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");
  curl_easy_setopt(handle, CURLOPT_POST, 1L);
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(handle, CURLOPT_TIMEOUT, CHAT_BOT_HTTP_TIMEOUT);
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, CHAT_BOT_HTTP_TIMEOUT);
  curl_easy_setopt(handle, CURLOPT_USERAGENT, "ssh-chatter-bot/1.0");

  chat_bot_buffer_state_t state = {.data = NULL, .size = 0U};
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, chat_bot_write_callback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &state);

  CURLcode perform_result = curl_easy_perform(handle);
  bool success = false;
  if (perform_result == CURLE_OK && state.data != NULL) {
    if (chat_bot_extract_reply(state.data, response, response_length)) {
      chat_bot_trim_message(response);
      success = response[0] != '\0';
    }
  } else {
    const char *error_text = curl_easy_strerror(perform_result);
    humanized_log_error("chat-bot", error_text, perform_result);
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(handle);
  if (state.data != NULL) {
    free(state.data);
  }

  return success;
}

static void chat_bot_on_message(client_connection_t *connection, const chat_history_entry_t *entry) {
  if (connection == NULL || connection->user_data == NULL || entry == NULL) {
    return;
  }

  if (!entry->is_user_message) {
    return;
  }

  chat_bot_t *bot = (chat_bot_t *)connection->user_data;
  if (!bot->enabled) {
    return;
  }

  if (strncmp(entry->username, bot->name, sizeof(entry->username)) == 0) {
    return;
  }

  if (entry->message[0] == '\0') {
    return;
  }

  pthread_mutex_lock(&bot->lock);
  if (bot->queue_count >= CHAT_BOT_QUEUE_LENGTH) {
    size_t drop_index = bot->queue_start;
    bot->queue_start = (bot->queue_start + 1U) % CHAT_BOT_QUEUE_LENGTH;
    bot->queue_count--;
    bot->queue[drop_index].username[0] = '\0';
    bot->queue[drop_index].content[0] = '\0';
    bot->queue[drop_index].from_bot = false;
  }

  size_t insert_index = (bot->queue_start + bot->queue_count) % CHAT_BOT_QUEUE_LENGTH;
  snprintf(bot->queue[insert_index].username, sizeof(bot->queue[insert_index].username), "%s", entry->username);
  snprintf(bot->queue[insert_index].content, sizeof(bot->queue[insert_index].content), "%s", entry->message);
  bot->queue[insert_index].from_bot = false;
  chat_bot_record_memory_locked(bot, &bot->queue[insert_index]);
  bot->queue_count++;
  pthread_cond_signal(&bot->cond);
  pthread_mutex_unlock(&bot->lock);
}

static void chat_bot_on_detach(client_connection_t *connection) {
  (void)connection;
}

static void *chat_bot_thread_main(void *arg) {
  chat_bot_t *bot = (chat_bot_t *)arg;
  if (bot == NULL) {
    return NULL;
  }

  while (true) {
    pthread_mutex_lock(&bot->lock);
    while (bot->queue_count == 0U && !bot->shutting_down) {
      pthread_cond_wait(&bot->cond, &bot->lock);
    }
    if (bot->shutting_down) {
      pthread_mutex_unlock(&bot->lock);
      break;
    }

    chat_bot_message_t message = bot->queue[bot->queue_start];
    chat_bot_memory_snapshot_t snapshot = {0};
    chat_bot_snapshot_memory(bot, &snapshot);
    bot->queue_start = (bot->queue_start + 1U) % CHAT_BOT_QUEUE_LENGTH;
    if (bot->queue_count > 0U) {
      bot->queue_count--;
    }
    pthread_mutex_unlock(&bot->lock);

    char reply[SSH_CHATTER_MESSAGE_LIMIT];
    reply[0] = '\0';
    if (chat_bot_generate_reply(bot, &message, &snapshot, reply, sizeof(reply))) {
      host_post_client_message(bot->host, bot->name, reply, NULL, NULL, true);

      chat_bot_message_t reply_message = {0};
      snprintf(reply_message.username, sizeof(reply_message.username), "%s", bot->name);
      snprintf(reply_message.content, sizeof(reply_message.content), "%s", reply);
      reply_message.from_bot = true;
      pthread_mutex_lock(&bot->lock);
      chat_bot_record_memory_locked(bot, &reply_message);
      pthread_mutex_unlock(&bot->lock);
    }
  }

  return NULL;
}

chat_bot_t *chat_bot_create(struct host *host, client_manager_t *manager) {
  if (host == NULL || manager == NULL) {
    return NULL;
  }

  chat_bot_t *bot = (chat_bot_t *)calloc(1U, sizeof(chat_bot_t));
  if (bot == NULL) {
    return NULL;
  }

  bot->host = host;
  bot->manager = manager;
  pthread_mutex_init(&bot->lock, NULL);
  pthread_cond_init(&bot->cond, NULL);
  chat_bot_init_queue(bot);
  chat_bot_reset_memory(bot);
  chat_bot_resolve_memory_path(bot);
  snprintf(bot->name, sizeof(bot->name), "%s", CHAT_BOT_DEFAULT_NAME);
  snprintf(bot->model, sizeof(bot->model), "%s", CHAT_BOT_DEFAULT_MODEL);
  snprintf(bot->system_prompt, sizeof(bot->system_prompt), "%s", CHAT_BOT_PROMPT_DEFAULT);
  bot->api_key[0] = '\0';
  bot->thread_started = false;
  bot->shutting_down = false;
  bot->enabled = false;
  bot->registered = false;
  memset(&bot->connection, 0, sizeof(bot->connection));
  bot->connection.kind = CLIENT_KIND_BOT;
  bot->connection.receive_system_messages = false;
  bot->connection.on_message = chat_bot_on_message;
  bot->connection.on_detach = chat_bot_on_detach;
  bot->connection.user_data = bot;
  bot->connection.active = false;
  bot->connection.owner = NULL;
  snprintf(bot->connection.identifier, sizeof(bot->connection.identifier), "%s", "chatgpt");
  bot->has_captcha_hint = false;
  bot->captcha_question[0] = '\0';
  bot->captcha_answer[0] = '\0';
  bot->captcha_hint_time.tv_sec = 0;
  bot->captcha_hint_time.tv_nsec = 0L;

  chat_bot_load_env(bot);
  chat_bot_update_name_lower(bot);
  bot->enabled = bot->api_key[0] != '\0';
  if (!bot->enabled) {
    printf("[chat-bot] OPENAI_API_KEY missing in %s; bot disabled.\n", CHAT_BOT_ENV_PATH);
  } else {
    if (!chat_bot_load_memory(bot)) {
      chat_bot_seed_history(bot);
    }
  }

  return bot;
}

bool chat_bot_start(chat_bot_t *bot) {
  if (bot == NULL || !bot->enabled) {
    return false;
  }

  if (!bot->registered) {
    if (!client_manager_register(bot->manager, &bot->connection)) {
      return false;
    }
    bot->registered = true;
  }

  if (bot->thread_started) {
    return true;
  }

  if (pthread_create(&bot->thread, NULL, chat_bot_thread_main, bot) != 0) {
    client_manager_unregister(bot->manager, &bot->connection);
    bot->registered = false;
    humanized_log_error("chat-bot", "failed to start bot thread", errno);
    return false;
  }

  bot->thread_started = true;
  printf("[chat-bot] ChatGPT bot '%s' is active.\n", bot->name);
  return true;
}

void chat_bot_shutdown(chat_bot_t *bot) {
  if (bot == NULL) {
    return;
  }

  pthread_mutex_lock(&bot->lock);
  bot->shutting_down = true;
  chat_bot_save_memory_locked(bot);
  pthread_cond_broadcast(&bot->cond);
  pthread_mutex_unlock(&bot->lock);

  if (bot->thread_started) {
    pthread_join(bot->thread, NULL);
    bot->thread_started = false;
  }

  if (bot->registered && bot->manager != NULL) {
    client_manager_unregister(bot->manager, &bot->connection);
    bot->registered = false;
  }

  bot->enabled = false;
}

void chat_bot_destroy(chat_bot_t *bot) {
  if (bot == NULL) {
    return;
  }

  chat_bot_shutdown(bot);
  pthread_mutex_destroy(&bot->lock);
  pthread_cond_destroy(&bot->cond);
  free(bot);
}

bool chat_bot_is_enabled(const chat_bot_t *bot) {
  if (bot == NULL) {
    return false;
  }
  return bot->enabled;
}

void chat_bot_set_captcha_hint(chat_bot_t *bot, const char *question, const char *answer) {
  if (bot == NULL) {
    return;
  }

  pthread_mutex_lock(&bot->lock);
  if (question != NULL) {
    snprintf(bot->captcha_question, sizeof(bot->captcha_question), "%s", question);
  } else {
    bot->captcha_question[0] = '\0';
  }
  if (answer != NULL) {
    snprintf(bot->captcha_answer, sizeof(bot->captcha_answer), "%s", answer);
  } else {
    bot->captcha_answer[0] = '\0';
  }

  bot->has_captcha_hint = bot->captcha_question[0] != '\0' && bot->captcha_answer[0] != '\0';
  if (bot->has_captcha_hint) {
    if (clock_gettime(CLOCK_REALTIME, &bot->captcha_hint_time) != 0) {
      bot->captcha_hint_time.tv_sec = time(NULL);
      bot->captcha_hint_time.tv_nsec = 0L;
    }
  } else {
    bot->captcha_hint_time.tv_sec = 0;
    bot->captcha_hint_time.tv_nsec = 0L;
  }
  pthread_mutex_unlock(&bot->lock);
}

bool chat_bot_snapshot_captcha_hint(chat_bot_t *bot, char *question, size_t question_length, char *answer,
                                    size_t answer_length, struct timespec *timestamp) {
  if (bot == NULL) {
    return false;
  }

  pthread_mutex_lock(&bot->lock);
  bool has_hint = bot->has_captcha_hint;
  if (has_hint) {
    if (question != NULL && question_length > 0U) {
      snprintf(question, question_length, "%s", bot->captcha_question);
    }
    if (answer != NULL && answer_length > 0U) {
      snprintf(answer, answer_length, "%s", bot->captcha_answer);
    }
    if (timestamp != NULL) {
      *timestamp = bot->captcha_hint_time;
    }
  }
  pthread_mutex_unlock(&bot->lock);
  return has_hint;
}
