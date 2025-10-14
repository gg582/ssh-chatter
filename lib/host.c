#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "host.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <wchar.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "humanized/humanized.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif

#define ANSI_CLEAR_LINE "\033[2K"

#define SSH_CHATTER_MESSAGE_BOX_MAX_LINES 32U
#define SSH_CHATTER_MESSAGE_BOX_PADDING 2U
#define SSH_CHATTER_IMAGE_PREVIEW_WIDTH 48U
#define SSH_CHATTER_IMAGE_PREVIEW_HEIGHT 48U
#define SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN 128U

typedef struct {
  const char *name;
  const char *code;
} color_entry_t;

static const color_entry_t USER_COLOR_MAP[] = {
    {"red", ANSI_RED},       {"green", ANSI_GREEN},   {"yellow", ANSI_YELLOW},
    {"blue", ANSI_BLUE},     {"magenta", ANSI_MAGENTA}, {"cyan", ANSI_CYAN},
    {"white", ANSI_WHITE},   {"grey", ANSI_GREY},     {"default", ANSI_DEFAULT},
};

static const color_entry_t HIGHLIGHT_COLOR_MAP[] = {
    {"black", ANSI_BG_BLACK},     {"red", ANSI_BG_RED},       {"green", ANSI_BG_GREEN},
    {"yellow", ANSI_BG_YELLOW},   {"blue", ANSI_BG_BLUE},     {"magenta", ANSI_BG_MAGENTA},
    {"cyan", ANSI_BG_CYAN},       {"white", ANSI_BG_WHITE},   {"grey", ANSI_BG_GREY},
    {"default", ANSI_BG_DEFAULT},
};

typedef struct palette_descriptor {
  const char *name;
  const char *description;
  const char *user_color_name;
  const char *user_highlight_name;
  bool user_is_bold;
  const char *system_fg_name;
  const char *system_bg_name;
  const char *system_highlight_name;
  bool system_is_bold;
} palette_descriptor_t;

static const palette_descriptor_t PALETTE_DEFINITIONS[] = {
    {"moe", "Soft magenta accents with playful highlights", "magenta", "white", true, "white", "magenta", "cyan", true},
    {"clean", "Balanced neutral palette with subtle cyan focus", "default", "default", false, "default", "default", "cyan", false},
    {"adwaita", "Bright background inspired by GNOME Adwaita", "blue", "default", false, "blue", "white", "grey", false},
    {"win10", "High contrast palette reminiscent of Windows 10", "cyan", "blue", true, "white", "blue", "yellow", true},
    {"korea", "Taegeuk-inspired white base with red and blue accents", "blue", "white", true, "blue", "white", "red", true},
};

typedef int (*accept_channel_fn_t)(ssh_message, ssh_channel);

#if defined(__GNUC__)
extern int ssh_message_channel_request_open_reply_accept_channel(ssh_message message,
                                                                 ssh_channel channel)
    __attribute__((weak));
#endif

static void resolve_accept_channel_once(void);
static accept_channel_fn_t g_accept_channel_fn = NULL;
static pthread_once_t g_accept_channel_once = PTHREAD_ONCE_INIT;

static accept_channel_fn_t resolve_accept_channel_fn(void) {
  pthread_once(&g_accept_channel_once, resolve_accept_channel_once);
  return g_accept_channel_fn;
}

static void resolve_accept_channel_once(void) {
#if defined(__GNUC__)
  if (ssh_message_channel_request_open_reply_accept_channel != NULL) {
    g_accept_channel_fn = ssh_message_channel_request_open_reply_accept_channel;
    return;
  }
#endif

  static const char *kSymbol = "ssh_message_channel_request_open_reply_accept_channel";

#if defined(RTLD_DEFAULT)
  g_accept_channel_fn = (accept_channel_fn_t)dlsym(RTLD_DEFAULT, kSymbol);
  if (g_accept_channel_fn != NULL) {
    return;
  }
#endif

  const char *candidates[] = {"libssh.so.4", "libssh.so", "libssh.dylib"};
  for (size_t idx = 0; idx < sizeof(candidates) / sizeof(candidates[0]); ++idx) {
    const char *name = candidates[idx];
    void *handle = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
      handle = dlopen(name, RTLD_LAZY);
    }
    if (handle == NULL) {
      continue;
    }

    g_accept_channel_fn = (accept_channel_fn_t)dlsym(handle, kSymbol);
    if (g_accept_channel_fn != NULL) {
      return;
    }
  }
}

static void trim_whitespace_inplace(char *text);
static const char *lookup_color_code(const color_entry_t *entries, size_t entry_count, const char *name);
static bool parse_bool_token(const char *token, bool *value);
static void session_send_line(ssh_channel channel, const char *message);
static void session_send_plain_line(session_ctx_t *ctx, const char *message);
static void session_send_system_line(session_ctx_t *ctx, const char *message);
static void session_send_raw_text(session_ctx_t *ctx, const char *text);
static void session_render_banner(session_ctx_t *ctx);
static void session_render_separator(session_ctx_t *ctx, const char *label);
static void session_render_prompt(session_ctx_t *ctx, bool include_separator);
static void session_refresh_input_line(session_ctx_t *ctx);
static void session_set_input_text(session_ctx_t *ctx, const char *text);
static void session_local_echo_char(session_ctx_t *ctx, char ch);
static void session_local_backspace(session_ctx_t *ctx);
static void session_clear_input(session_ctx_t *ctx);
static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch);
static void session_history_record(session_ctx_t *ctx, const char *line);
static void session_history_navigate(session_ctx_t *ctx, int direction);
static void session_scrollback_navigate(session_ctx_t *ctx, int direction);
static void chat_history_entry_prepare_user(chat_history_entry_t *entry, const session_ctx_t *from, const char *message);
static bool host_history_record_user(host_t *host, const session_ctx_t *from, const char *message, chat_history_entry_t *stored_entry);
static bool host_history_commit_entry(host_t *host, chat_history_entry_t *entry, chat_history_entry_t *stored_entry);
static void host_history_append_locked(host_t *host, const chat_history_entry_t *entry);
static void chat_room_broadcast_entry(chat_room_t *room, const chat_history_entry_t *entry, const session_ctx_t *from);
static bool host_history_apply_reaction(host_t *host, uint64_t message_id, size_t reaction_index, chat_history_entry_t *updated_entry);
static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length);
static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source,
                                              const char *label, const char *message);
static session_ctx_t *chat_room_find_user(chat_room_t *room, const char *username);
static bool host_is_ip_banned(host_t *host, const char *ip);
static bool host_is_username_banned(host_t *host, const char *username);
static bool host_add_ban_entry(host_t *host, const char *username, const char *ip);
static bool host_remove_ban_entry(host_t *host, const char *token);
static bool session_is_private_ipv4(const unsigned char octets[4]);
static bool session_is_lan_client(const char *ip);
static void session_assign_lan_privileges(session_ctx_t *ctx);
static void session_apply_theme_defaults(session_ctx_t *ctx);
static void session_apply_system_theme_defaults(session_ctx_t *ctx);
static void session_apply_saved_preferences(session_ctx_t *ctx);
static void session_dispatch_command(session_ctx_t *ctx, const char *line);
static void session_handle_exit(session_ctx_t *ctx);
static void session_handle_nick(session_ctx_t *ctx, const char *arguments);
static void session_handle_pm(session_ctx_t *ctx, const char *arguments);
static void session_handle_motd(session_ctx_t *ctx);
static void session_handle_system_color(session_ctx_t *ctx, const char *arguments);
static void session_handle_palette(session_ctx_t *ctx, const char *arguments);
static void session_handle_pardon(session_ctx_t *ctx, const char *arguments);
static void session_handle_usercount(session_ctx_t *ctx);
static void session_handle_search(session_ctx_t *ctx, const char *arguments);
static void session_handle_image(session_ctx_t *ctx, const char *arguments);
static void session_handle_video(session_ctx_t *ctx, const char *arguments);
static void session_handle_audio(session_ctx_t *ctx, const char *arguments);
static void session_handle_files(session_ctx_t *ctx, const char *arguments);
static void session_handle_reaction(session_ctx_t *ctx, size_t reaction_index, const char *arguments);
static void session_handle_image_to_ascii(session_ctx_t *ctx, const char *arguments);
static void session_handle_today(session_ctx_t *ctx);
static void session_handle_date(session_ctx_t *ctx, const char *arguments);
static void session_handle_os(session_ctx_t *ctx, const char *arguments);
static void session_handle_getos(session_ctx_t *ctx, const char *arguments);
static void session_handle_pair(session_ctx_t *ctx);
static void session_handle_connected(session_ctx_t *ctx);
static void session_handle_poll(session_ctx_t *ctx, const char *arguments);
static void session_handle_vote(session_ctx_t *ctx, size_t option_index);
static bool session_line_is_exit_command(const char *line);
static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line);
static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count);
static size_t session_utf8_prev_char_len(const char *buffer, size_t length);
static int session_utf8_char_width(const char *bytes, size_t length);
static void host_history_record_system(host_t *host, const char *message);
static void session_send_history(session_ctx_t *ctx);
static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry);
static void chat_room_broadcast_reaction_update(host_t *host, const chat_history_entry_t *entry);
static user_preference_t *host_find_preference_locked(host_t *host, const char *username);
static user_preference_t *host_ensure_preference_locked(host_t *host, const char *username);
static void host_store_user_theme(host_t *host, const session_ctx_t *ctx);
static void host_store_system_theme(host_t *host, const session_ctx_t *ctx);
static void host_store_user_os(host_t *host, const session_ctx_t *ctx);
static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry);
static const char *chat_attachment_type_label(chat_attachment_type_t type);
static void host_state_resolve_path(host_t *host);
static void host_state_load(host_t *host);
static void host_state_save_locked(host_t *host);
static bool host_try_load_motd_from_path(host_t *host, const char *path);

static const uint32_t HOST_STATE_MAGIC = 0x53484354U; /* 'SHCT' */
static const uint32_t HOST_STATE_VERSION = 4U;

#define HOST_STATE_SOUND_ALIAS_LEN 32U

typedef struct host_state_header_v1 {
  uint32_t magic;
  uint32_t version;
  uint32_t history_count;
  uint32_t preference_count;
} host_state_header_v1_t;

typedef struct host_state_header {
  host_state_header_v1_t base;
  uint32_t legacy_sound_count;
  uint32_t reserved;
  uint64_t next_message_id;
} host_state_header_t;

typedef struct host_state_history_entry_v1 {
  uint8_t is_user_message;
  uint8_t user_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char message[SSH_CHATTER_MESSAGE_LIMIT];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
} host_state_history_entry_v1_t;

typedef struct host_state_history_entry_v2 {
  host_state_history_entry_v1_t base;
  uint64_t message_id;
  uint8_t attachment_type;
  char attachment_target[SSH_CHATTER_ATTACHMENT_TARGET_LEN];
  char attachment_caption[SSH_CHATTER_ATTACHMENT_CAPTION_LEN];
  char sound_alias[HOST_STATE_SOUND_ALIAS_LEN];
  uint32_t reaction_counts[SSH_CHATTER_REACTION_KIND_COUNT];
} host_state_history_entry_v2_t;

typedef struct host_state_history_entry_v3 {
  host_state_history_entry_v1_t base;
  uint64_t message_id;
  uint8_t attachment_type;
  uint8_t reserved[7];
  char attachment_target[SSH_CHATTER_ATTACHMENT_TARGET_LEN];
  char attachment_caption[SSH_CHATTER_ATTACHMENT_CAPTION_LEN];
  uint32_t reaction_counts[SSH_CHATTER_REACTION_KIND_COUNT];
} host_state_history_entry_v3_t;

typedef struct host_state_preference_entry_v3 {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
} host_state_preference_entry_v3_t;

typedef struct host_state_preference_entry {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int32_t daily_year;
  int32_t daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int32_t last_poll_choice;
} host_state_preference_entry_t;


typedef struct reaction_descriptor {
  const char *command;
  const char *label;
  const char *icon;
} reaction_descriptor_t;

static const reaction_descriptor_t REACTION_DEFINITIONS[SSH_CHATTER_REACTION_KIND_COUNT] = {
    {"good", "good", "👍"},   {"sad", "sad", "😢"},   {"cool", "cool", "😎"},
    {"angry", "angry", "😠"}, {"checked", "checked", "✅"},
    {"love", "love", "❤️"},   {"wtf", "wtf", "🤨"},
};

typedef struct os_descriptor {
  const char *name;
  const char *display;
} os_descriptor_t;

static const os_descriptor_t OS_CATALOG[] = {
    {"windows", "Windows"},      {"macos", "macOS"},      {"linux", "Linux"},
    {"freebsd", "FreeBSD"},      {"ios", "iOS"},          {"android", "Android"},
    {"watchos", "watchOS"},      {"solaris", "Solaris"},  {"openbsd", "OpenBSD"},
    {"netbsd", "NetBSD"},        {"dragonflybsd", "DragonFlyBSD"},
    {"reactos", "ReactOS"},      {"tyzen", "Tyzen"},
};

static const os_descriptor_t *session_lookup_os_descriptor(const char *name);

static const char *DAILY_FUNCTIONS[] = {"sin",   "cos",   "tan",   "sqrt",  "log",   "exp",     "printf",
                                        "malloc", "free",  "memcpy", "strncpy", "qsort", "fopen",   "close",
                                        "select", "poll",  "fork",  "exec",  "pthread_create", "strtok"};

static void chat_room_init(chat_room_t *room) {
  if (room == NULL) {
    return;
  }
  pthread_mutex_init(&room->lock, NULL);
  room->member_count = 0U;
  for (size_t idx = 0; idx < SSH_CHATTER_MAX_USERS; ++idx) {
    room->members[idx] = NULL;
  }
}

static void session_describe_peer(ssh_session session, char *buffer, size_t len) {
  if (buffer == NULL || len == 0U) {
    return;
  }

  buffer[0] = '\0';
  if (session == NULL) {
    return;
  }

  const int socket_fd = ssh_get_fd(session);
  if (socket_fd < 0) {
    return;
  }

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  if (getpeername(socket_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
    return;
  }

  char host[NI_MAXHOST];
  if (getnameinfo((struct sockaddr *)&addr, addr_len, host, sizeof(host), NULL, 0,
                  NI_NUMERICHOST) != 0) {
    return;
  }

  strncpy(buffer, host, len - 1U);
  buffer[len - 1U] = '\0';
}

static bool session_is_private_ipv4(const unsigned char octets[4]) {
  if (octets == NULL) {
    return false;
  }

  if (octets[0] == 10U || octets[0] == 127U) {
    return true;
  }

  if (octets[0] == 172U && octets[1] >= 16U && octets[1] <= 31U) {
    return true;
  }

  if ((octets[0] == 192U && octets[1] == 168U) || (octets[0] == 169U && octets[1] == 254U)) {
    return true;
  }

  return false;
}

static bool session_is_lan_client(const char *ip) {
  if (ip == NULL || ip[0] == '\0') {
    return false;
  }

  struct in_addr addr4;
  if (inet_pton(AF_INET, ip, &addr4) == 1) {
    unsigned char octets[4];
    memcpy(octets, &addr4.s_addr, sizeof(octets));
    return session_is_private_ipv4(octets);
  }

  struct in6_addr addr6;
  if (inet_pton(AF_INET6, ip, &addr6) != 1) {
    return false;
  }

  if (IN6_IS_ADDR_LOOPBACK(&addr6) || IN6_IS_ADDR_LINKLOCAL(&addr6)) {
    return true;
  }

  if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
    return session_is_private_ipv4(&addr6.s6_addr[12]);
  }

  const unsigned char first_byte = addr6.s6_addr[0];
  if ((first_byte & 0xfeU) == 0xfcU) { // fc00::/7 unique local
    return true;
  }

  return false;
}

static void session_assign_lan_privileges(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (session_is_lan_client(ctx->client_ip)) {
    ctx->user.is_operator = true;
    ctx->user.is_lan_operator = true;
    ctx->auth.is_operator = true;
  }
}

static void chat_room_add(chat_room_t *room, session_ctx_t *session) {
  if (room == NULL || session == NULL) {
    return;
  }

  pthread_mutex_lock(&room->lock);
  if (room->member_count < SSH_CHATTER_MAX_USERS) {
    room->members[room->member_count++] = session;
  }
  pthread_mutex_unlock(&room->lock);
}

static void chat_room_remove(chat_room_t *room, const session_ctx_t *session) {
  if (room == NULL || session == NULL) {
    return;
  }

  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    if (room->members[idx] == session) {
      for (size_t shift = idx; shift + 1U < room->member_count; ++shift) {
        room->members[shift] = room->members[shift + 1U];
      }
      room->members[room->member_count - 1U] = NULL;
      room->member_count--;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);
}

static void chat_room_broadcast(chat_room_t *room, const char *message, const session_ctx_t *from) {
  if (room == NULL || message == NULL) {
    return;
  }

  session_ctx_t *targets[SSH_CHATTER_MAX_USERS];
  size_t target_count = 0U;

  chat_history_entry_t entry = {0};
  if (from != NULL) {
    chat_history_entry_prepare_user(&entry, from, message);
  }

  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    session_ctx_t *member = room->members[idx];
    if (member == NULL || member->channel == NULL) {
      continue;
    }
    if (from != NULL && member == from) {
      continue;
    }
    if (target_count < SSH_CHATTER_MAX_USERS) {
      targets[target_count++] = member;
    }
  }
  pthread_mutex_unlock(&room->lock);

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    if (from != NULL) {
      session_send_history_entry(member, &entry);
    } else {
      session_send_system_line(member, message);
    }

    if (member->history_scroll_position == 0U) {
      session_refresh_input_line(member);
    }
  }

  if (from != NULL) {
    printf("[broadcast:%s] %s\n", from->user.name, message);
  } else {
    printf("[broadcast] %s\n", message);
  }
}

static void chat_room_broadcast_entry(chat_room_t *room, const chat_history_entry_t *entry, const session_ctx_t *from) {
  if (room == NULL || entry == NULL) {
    return;
  }

  session_ctx_t *targets[SSH_CHATTER_MAX_USERS];
  size_t target_count = 0U;

  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    session_ctx_t *member = room->members[idx];
    if (member == NULL || member->channel == NULL) {
      continue;
    }
    if (from != NULL && member == from) {
      continue;
    }
    if (target_count < SSH_CHATTER_MAX_USERS) {
      targets[target_count++] = member;
    }
  }
  pthread_mutex_unlock(&room->lock);

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    session_send_history_entry(member, entry);
    if (member->history_scroll_position == 0U) {
      session_refresh_input_line(member);
    }
  }

  if (entry->is_user_message) {
    const char *message_text = entry->message;
    char fallback[SSH_CHATTER_MESSAGE_LIMIT + 64];
    if ((message_text == NULL || message_text[0] == '\0') && entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(fallback, sizeof(fallback), "shared a %s", label);
      message_text = fallback;
    } else if (message_text == NULL) {
      message_text = "";
    }

    printf("[broadcast:%s#%" PRIu64 "] %s\n", entry->username, entry->message_id, message_text);
    if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      printf("           %s: %s\n", label, entry->attachment_target);
    }
  }
}

static void chat_room_broadcast_reaction_update(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  char summary[SSH_CHATTER_MESSAGE_LIMIT];
  if (!chat_history_entry_build_reaction_summary(entry, summary, sizeof(summary))) {
    return;
  }

  char line[SSH_CHATTER_MESSAGE_LIMIT + 64];
  if (entry->message_id > 0U) {
    snprintf(line, sizeof(line), "    ↳ [#%" PRIu64 "] reactions: %s", entry->message_id, summary);
  } else {
    snprintf(line, sizeof(line), "    ↳ reactions: %s", summary);
  }

  chat_room_broadcast(&host->room, line, NULL);
}

static size_t host_history_snapshot(host_t *host, chat_history_entry_t *snapshot, size_t capacity) {
  if (host == NULL || snapshot == NULL || capacity == 0U) {
    return 0U;
  }

  size_t count = 0U;

  pthread_mutex_lock(&host->lock);
  count = host->history_count;
  if (count > capacity) {
    count = capacity;
  }
  for (size_t idx = 0U; idx < count; ++idx) {
    size_t history_index = (host->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    snapshot[idx] = host->history[history_index];
  }
  pthread_mutex_unlock(&host->lock);

  return count;
}

static void host_history_append_locked(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  size_t insert_index = 0U;
  if (host->history_count < SSH_CHATTER_HISTORY_LIMIT) {
    insert_index = (host->history_start + host->history_count) % SSH_CHATTER_HISTORY_LIMIT;
    host->history_count++;
  } else {
    insert_index = host->history_start;
    host->history_start = (host->history_start + 1U) % SSH_CHATTER_HISTORY_LIMIT;
  }

  host->history[insert_index] = *entry;

  host_state_save_locked(host);
}

static void chat_history_entry_prepare_user(chat_history_entry_t *entry, const session_ctx_t *from, const char *message) {
  if (entry == NULL || from == NULL) {
    return;
  }

  memset(entry, 0, sizeof(*entry));
  entry->is_user_message = true;
  if (message != NULL) {
    snprintf(entry->message, sizeof(entry->message), "%s", message);
  }
  snprintf(entry->username, sizeof(entry->username), "%s", from->user.name);
  entry->user_color_code = from->user_color_code;
  entry->user_highlight_code = from->user_highlight_code;
  entry->user_is_bold = from->user_is_bold;
  snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", from->user_color_name);
  snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s", from->user_highlight_name);
  entry->attachment_type = CHAT_ATTACHMENT_NONE;
  entry->message_id = 0U;
}

static bool host_history_commit_entry(host_t *host, chat_history_entry_t *entry, chat_history_entry_t *stored_entry) {
  if (host == NULL || entry == NULL) {
    return false;
  }

  host_history_normalize_entry(host, entry);

  pthread_mutex_lock(&host->lock);
  if (entry->is_user_message) {
    if (host->next_message_id == 0U) {
      host->next_message_id = 1U;
    }
    entry->message_id = host->next_message_id++;
  } else {
    entry->message_id = 0U;
  }

  host_history_append_locked(host, entry);

  if (stored_entry != NULL) {
    *stored_entry = *entry;
  }

  pthread_mutex_unlock(&host->lock);
  return true;
}

static bool host_history_record_user(host_t *host, const session_ctx_t *from, const char *message,
                                     chat_history_entry_t *stored_entry) {
  if (host == NULL || from == NULL || message == NULL || message[0] == '\0') {
    return false;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, from, message);
  return host_history_commit_entry(host, &entry, stored_entry);
}

static void host_history_record_system(host_t *host, const char *message) {
  if (host == NULL || message == NULL || message[0] == '\0') {
    return;
  }

  chat_history_entry_t entry = {0};
  entry.is_user_message = false;
  snprintf(entry.message, sizeof(entry.message), "%s", message);
  entry.user_color_name[0] = '\0';
  entry.user_highlight_name[0] = '\0';
  entry.attachment_type = CHAT_ATTACHMENT_NONE;
  entry.message_id = 0U;

  host_history_commit_entry(host, &entry, NULL);
}

static bool host_history_apply_reaction(host_t *host, uint64_t message_id, size_t reaction_index,
                                        chat_history_entry_t *updated_entry) {
  if (host == NULL || message_id == 0U || reaction_index >= SSH_CHATTER_REACTION_KIND_COUNT) {
    return false;
  }

  bool applied = false;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < host->history_count; ++idx) {
    size_t history_index = (host->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    chat_history_entry_t *entry = &host->history[history_index];
    if (!entry->is_user_message) {
      continue;
    }
    if (entry->message_id != message_id) {
      continue;
    }

    if (entry->reaction_counts[reaction_index] < UINT32_MAX) {
      entry->reaction_counts[reaction_index] += 1U;
    }

    if (updated_entry != NULL) {
      *updated_entry = *entry;
    }

    host_state_save_locked(host);
    applied = true;
    break;
  }
  pthread_mutex_unlock(&host->lock);

  return applied;
}

static bool host_history_find_entry_by_id(host_t *host, uint64_t message_id, chat_history_entry_t *out_entry) {
  if (host == NULL || message_id == 0U) {
    return false;
  }

  bool found = false;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < host->history_count; ++idx) {
    size_t history_index = (host->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    const chat_history_entry_t *entry = &host->history[history_index];
    if (!entry->is_user_message) {
      continue;
    }
    if (entry->message_id != message_id) {
      continue;
    }

    if (out_entry != NULL) {
      *out_entry = *entry;
    }
    found = true;
    break;
  }
  pthread_mutex_unlock(&host->lock);

  return found;
}

static void session_apply_theme_defaults(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;

  ctx->user_color_code = host->user_theme.userColor;
  ctx->user_highlight_code = host->user_theme.highlight;
  ctx->user_is_bold = host->user_theme.isBold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", host->default_user_color_name);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", host->default_user_highlight_name);

  session_apply_system_theme_defaults(ctx);
}

static void session_apply_system_theme_defaults(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;

  ctx->system_fg_code = host->system_theme.foregroundColor;
  ctx->system_bg_code = host->system_theme.backgroundColor;
  ctx->system_highlight_code = host->system_theme.highlightColor;
  ctx->system_is_bold = host->system_theme.isBold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", host->default_system_fg_name);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", host->default_system_bg_name);
  snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", host->default_system_highlight_name);
}

static user_preference_t *host_find_preference_locked(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use) {
      continue;
    }

    if (strncmp(pref->username, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      return pref;
    }
  }

  return NULL;
}

static user_preference_t *host_ensure_preference_locked(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return NULL;
  }

  user_preference_t *existing = host_find_preference_locked(host, username);
  if (existing != NULL) {
    return existing;
  }

  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    user_preference_t *pref = &host->preferences[idx];
    if (pref->in_use) {
      continue;
    }

    memset(pref, 0, sizeof(*pref));
    pref->in_use = true;
    pref->last_poll_choice = -1;
    snprintf(pref->username, sizeof(pref->username), "%s", username);
    if (host->preference_count < SSH_CHATTER_MAX_PREFERENCES) {
      ++host->preference_count;
    }
    return pref;
  }

  return NULL;
}

static void host_store_user_theme(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->has_user_theme = true;
    snprintf(pref->user_color_name, sizeof(pref->user_color_name), "%s", ctx->user_color_name);
    snprintf(pref->user_highlight_name, sizeof(pref->user_highlight_name), "%s", ctx->user_highlight_name);
    pref->user_is_bold = ctx->user_is_bold;
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_system_theme(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->has_system_theme = true;
    snprintf(pref->system_fg_name, sizeof(pref->system_fg_name), "%s", ctx->system_fg_name);
    snprintf(pref->system_bg_name, sizeof(pref->system_bg_name), "%s", ctx->system_bg_name);
    snprintf(pref->system_highlight_name, sizeof(pref->system_highlight_name), "%s", ctx->system_highlight_name);
    pref->system_is_bold = ctx->system_is_bold;
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_user_os(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    snprintf(pref->os_name, sizeof(pref->os_name), "%s", ctx->os_name);
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static bool host_lookup_user_os(host_t *host, const char *username, char *buffer, size_t length) {
  if (host == NULL || username == NULL || buffer == NULL || length == 0U) {
    return false;
  }

  bool found = false;

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_find_preference_locked(host, username);
  if (pref != NULL && pref->os_name[0] != '\0') {
    snprintf(buffer, length, "%s", pref->os_name);
    found = true;
  }
  pthread_mutex_unlock(&host->lock);

  if (found) {
    return true;
  }

  session_ctx_t *session = chat_room_find_user(&host->room, username);
  if (session != NULL && session->os_name[0] != '\0') {
    snprintf(buffer, length, "%s", session->os_name);
    return true;
  }

  return false;
}

static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  if (!entry->is_user_message) {
    entry->user_color_code = NULL;
    entry->user_highlight_code = NULL;
    entry->user_is_bold = false;
    entry->user_color_name[0] = '\0';
    entry->user_highlight_name[0] = '\0';
    return;
  }

  const char *color_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                             entry->user_color_name);
  if (color_code == NULL) {
    color_code = host->user_theme.userColor;
    snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", host->default_user_color_name);
  }

  const char *highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                entry->user_highlight_name);
  if (highlight_code == NULL) {
    highlight_code = host->user_theme.highlight;
    snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
             host->default_user_highlight_name);
  }

  entry->user_color_code = color_code;
  entry->user_highlight_code = highlight_code;
}

static void host_state_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *state_path = getenv("CHATTER_STATE_FILE");
  if (state_path == NULL || state_path[0] == '\0') {
    state_path = "chatter_state.dat";
  }

  int written = snprintf(host->state_file_path, sizeof(host->state_file_path), "%s", state_path);
  if (written < 0 || (size_t)written >= sizeof(host->state_file_path)) {
    humanized_log_error("host", "state file path is too long", ENAMETOOLONG);
    host->state_file_path[0] = '\0';
  }
}

static void host_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open state file", errno);
    return;
  }

  size_t preference_count = 0U;
  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    if (host->preferences[idx].in_use) {
      ++preference_count;
    }
  }

  host_state_header_t header = {0};
  header.base.magic = HOST_STATE_MAGIC;
  header.base.version = HOST_STATE_VERSION;
  header.base.history_count = (uint32_t)host->history_count;
  header.base.preference_count = (uint32_t)preference_count;
  header.legacy_sound_count = 0U;
  header.reserved = 0U;
  header.next_message_id = host->next_message_id;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  for (size_t idx = 0; success && idx < host->history_count; ++idx) {
    size_t history_index = (host->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    const chat_history_entry_t *entry = &host->history[history_index];

    host_state_history_entry_v3_t serialized = {0};
    serialized.base.is_user_message = entry->is_user_message ? 1U : 0U;
    serialized.base.user_is_bold = entry->user_is_bold ? 1U : 0U;
    snprintf(serialized.base.username, sizeof(serialized.base.username), "%s", entry->username);
    snprintf(serialized.base.message, sizeof(serialized.base.message), "%s", entry->message);
    snprintf(serialized.base.user_color_name, sizeof(serialized.base.user_color_name), "%s", entry->user_color_name);
    snprintf(serialized.base.user_highlight_name, sizeof(serialized.base.user_highlight_name), "%s",
             entry->user_highlight_name);
    serialized.message_id = entry->message_id;
    serialized.attachment_type = (uint8_t)entry->attachment_type;
    memset(serialized.reserved, 0, sizeof(serialized.reserved));
    snprintf(serialized.attachment_target, sizeof(serialized.attachment_target), "%s", entry->attachment_target);
    snprintf(serialized.attachment_caption, sizeof(serialized.attachment_caption), "%s", entry->attachment_caption);
    memcpy(serialized.reaction_counts, entry->reaction_counts, sizeof(serialized.reaction_counts));

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
    }
  }

  for (size_t idx = 0; success && idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    const user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use) {
      continue;
    }

    host_state_preference_entry_t serialized = {0};
    serialized.has_user_theme = pref->has_user_theme ? 1U : 0U;
    serialized.has_system_theme = pref->has_system_theme ? 1U : 0U;
    serialized.user_is_bold = pref->user_is_bold ? 1U : 0U;
    serialized.system_is_bold = pref->system_is_bold ? 1U : 0U;
    snprintf(serialized.username, sizeof(serialized.username), "%s", pref->username);
    snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", pref->user_color_name);
    snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", pref->user_highlight_name);
    snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", pref->system_fg_name);
    snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", pref->system_bg_name);
    snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
             pref->system_highlight_name);
    snprintf(serialized.os_name, sizeof(serialized.os_name), "%s", pref->os_name);
    serialized.daily_year = pref->daily_year;
    serialized.daily_yday = pref->daily_yday;
    snprintf(serialized.daily_function, sizeof(serialized.daily_function), "%s", pref->daily_function);
    serialized.last_poll_id = pref->last_poll_id;
    serialized.last_poll_choice = pref->last_poll_choice;

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      break;
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

  if (!success) {
    humanized_log_error("host", "failed to write state file", errno);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->state_file_path) != 0) {
    humanized_log_error("host", "failed to update state file", errno);
    unlink(temp_path);
  }
}

static void host_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->state_file_path[0] == '\0') {
    return;
  }

  FILE *fp = fopen(host->state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  host_state_header_v1_t base_header = {0};
  if (fread(&base_header, sizeof(base_header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (base_header.magic != HOST_STATE_MAGIC) {
    fclose(fp);
    return;
  }

  uint32_t version = base_header.version;
  if (version == 0U || version > HOST_STATE_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t history_count = base_header.history_count;
  uint32_t preference_count = base_header.preference_count;
  uint64_t next_message_id = 1U;

  if (version >= 2U) {
    uint32_t sound_count_raw = 0U;
    uint32_t reserved = 0U;
    uint64_t next_id_raw = 0U;
    if (fread(&sound_count_raw, sizeof(sound_count_raw), 1U, fp) != 1U ||
        fread(&reserved, sizeof(reserved), 1U, fp) != 1U ||
        fread(&next_id_raw, sizeof(next_id_raw), 1U, fp) != 1U) {
      fclose(fp);
      return;
    }
    next_message_id = next_id_raw;
  }

  if (history_count > SSH_CHATTER_HISTORY_LIMIT) {
    history_count = SSH_CHATTER_HISTORY_LIMIT;
  }
  if (preference_count > SSH_CHATTER_MAX_PREFERENCES) {
    preference_count = SSH_CHATTER_MAX_PREFERENCES;
  }

  pthread_mutex_lock(&host->lock);

  bool success = true;

  host->history_start = 0U;
  host->history_count = 0U;
  memset(host->history, 0, sizeof(host->history));

  for (uint32_t idx = 0; success && idx < history_count; ++idx) {
    chat_history_entry_t *entry = &host->history[idx % SSH_CHATTER_HISTORY_LIMIT];
    memset(entry, 0, sizeof(*entry));

    if (version >= 3U) {
      host_state_history_entry_v3_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.base.is_user_message != 0U;
      entry->user_is_bold = serialized.base.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.base.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.base.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.base.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
               serialized.base.user_highlight_name);
      entry->message_id = serialized.message_id;
      if (serialized.attachment_type > CHAT_ATTACHMENT_FILE) {
        entry->attachment_type = CHAT_ATTACHMENT_NONE;
      } else {
        entry->attachment_type = (chat_attachment_type_t)serialized.attachment_type;
      }
      snprintf(entry->attachment_target, sizeof(entry->attachment_target), "%s", serialized.attachment_target);
      snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.attachment_caption);
      memcpy(entry->reaction_counts, serialized.reaction_counts, sizeof(entry->reaction_counts));
    } else if (version == 2U) {
      host_state_history_entry_v2_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.base.is_user_message != 0U;
      entry->user_is_bold = serialized.base.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.base.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.base.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.base.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
               serialized.base.user_highlight_name);
      entry->message_id = serialized.message_id;
      if (serialized.attachment_type > CHAT_ATTACHMENT_AUDIO) {
        entry->attachment_type = CHAT_ATTACHMENT_NONE;
      } else {
        entry->attachment_type = (chat_attachment_type_t)serialized.attachment_type;
      }
      snprintf(entry->attachment_target, sizeof(entry->attachment_target), "%s", serialized.attachment_target);
      snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.attachment_caption);
      memcpy(entry->reaction_counts, serialized.reaction_counts, sizeof(entry->reaction_counts));
      if (serialized.sound_alias[0] != '\0' && entry->attachment_caption[0] == '\0') {
        snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.sound_alias);
      }
    } else {
      host_state_history_entry_v1_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.is_user_message != 0U;
      entry->user_is_bold = serialized.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s", serialized.user_highlight_name);
      entry->attachment_type = CHAT_ATTACHMENT_NONE;
      entry->message_id = 0U;
    }

    host_history_normalize_entry(host, entry);
    ++host->history_count;
  }

  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;

  for (uint32_t idx = 0; success && idx < preference_count; ++idx) {
    host_state_preference_entry_t serialized = {0};
    if (version >= 4U) {
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }
    } else {
      host_state_preference_entry_v3_t legacy = {0};
      if (fread(&legacy, sizeof(legacy), 1U, fp) != 1U) {
        success = false;
        break;
      }
      serialized.has_user_theme = legacy.has_user_theme;
      serialized.has_system_theme = legacy.has_system_theme;
      serialized.user_is_bold = legacy.user_is_bold;
      serialized.system_is_bold = legacy.system_is_bold;
      snprintf(serialized.username, sizeof(serialized.username), "%s", legacy.username);
      snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", legacy.user_color_name);
      snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", legacy.user_highlight_name);
      snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", legacy.system_fg_name);
      snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", legacy.system_bg_name);
      snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
               legacy.system_highlight_name);
      serialized.os_name[0] = '\0';
      serialized.daily_year = 0;
      serialized.daily_yday = 0;
      serialized.daily_function[0] = '\0';
      serialized.last_poll_id = 0U;
      serialized.last_poll_choice = -1;
    }

    if (host->preference_count >= SSH_CHATTER_MAX_PREFERENCES) {
      continue;
    }

    user_preference_t *pref = &host->preferences[host->preference_count];
    memset(pref, 0, sizeof(*pref));
    pref->in_use = true;
    pref->has_user_theme = serialized.has_user_theme != 0U;
    pref->has_system_theme = serialized.has_system_theme != 0U;
    pref->user_is_bold = serialized.user_is_bold != 0U;
    pref->system_is_bold = serialized.system_is_bold != 0U;
    snprintf(pref->username, sizeof(pref->username), "%s", serialized.username);
    snprintf(pref->user_color_name, sizeof(pref->user_color_name), "%s", serialized.user_color_name);
    snprintf(pref->user_highlight_name, sizeof(pref->user_highlight_name), "%s", serialized.user_highlight_name);
    snprintf(pref->system_fg_name, sizeof(pref->system_fg_name), "%s", serialized.system_fg_name);
    snprintf(pref->system_bg_name, sizeof(pref->system_bg_name), "%s", serialized.system_bg_name);
    snprintf(pref->system_highlight_name, sizeof(pref->system_highlight_name), "%s",
             serialized.system_highlight_name);
    snprintf(pref->os_name, sizeof(pref->os_name), "%s", serialized.os_name);
    pref->daily_year = serialized.daily_year;
    pref->daily_yday = serialized.daily_yday;
    snprintf(pref->daily_function, sizeof(pref->daily_function), "%s", serialized.daily_function);
    pref->last_poll_id = serialized.last_poll_id;
    pref->last_poll_choice = serialized.last_poll_choice;
    ++host->preference_count;
  }

  if (!success) {
    host->history_count = 0U;
    host->preference_count = 0U;
    memset(host->history, 0, sizeof(host->history));
    memset(host->preferences, 0, sizeof(host->preferences));
  }

  if (next_message_id == 0U) {
    next_message_id = (uint64_t)host->history_count + 1U;
  }
  if (next_message_id <= (uint64_t)host->history_count) {
    next_message_id = (uint64_t)host->history_count + 1U;
  }
  host->next_message_id = next_message_id;

  pthread_mutex_unlock(&host->lock);
  fclose(fp);
}
static void session_apply_saved_preferences(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  user_preference_t snapshot = {0};
  bool has_snapshot = false;

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_find_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    snapshot = *pref;
    has_snapshot = true;
  }
  pthread_mutex_unlock(&host->lock);

  if (!has_snapshot) {
    return;
  }

  if (snapshot.has_user_theme) {
    const char *color_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                               snapshot.user_color_name);
    const char *highlight_code = lookup_color_code(
        HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), snapshot.user_highlight_name);
    if (color_code != NULL && highlight_code != NULL) {
      ctx->user_color_code = color_code;
      ctx->user_highlight_code = highlight_code;
      ctx->user_is_bold = snapshot.user_is_bold;
      snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", snapshot.user_color_name);
      snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", snapshot.user_highlight_name);
    }
  }

  if (snapshot.has_system_theme) {
    const char *fg_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                            snapshot.system_fg_name);
    const char *bg_code = lookup_color_code(
        HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), snapshot.system_bg_name);
    if (fg_code != NULL && bg_code != NULL) {
      const char *highlight_code = ctx->system_highlight_code;
      if (snapshot.system_highlight_name[0] != '\0') {
        const char *candidate = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                 sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                 snapshot.system_highlight_name);
        if (candidate != NULL) {
          highlight_code = candidate;
        }
      }

      ctx->system_fg_code = fg_code;
      ctx->system_bg_code = bg_code;
      ctx->system_highlight_code = highlight_code;
      ctx->system_is_bold = snapshot.system_is_bold;
      snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", snapshot.system_fg_name);
      snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", snapshot.system_bg_name);
      if (snapshot.system_highlight_name[0] != '\0') {
        snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s",
                 snapshot.system_highlight_name);
      }
    }
  }

  if (snapshot.os_name[0] != '\0') {
    snprintf(ctx->os_name, sizeof(ctx->os_name), "%s", snapshot.os_name);
  }
  ctx->daily_year = snapshot.daily_year;
  ctx->daily_yday = snapshot.daily_yday;
  if (snapshot.daily_function[0] != '\0') {
    snprintf(ctx->daily_function, sizeof(ctx->daily_function), "%s", snapshot.daily_function);
  }
}

static void session_send_line(ssh_channel channel, const char *message) {
  if (channel == NULL || message == NULL) {
    return;
  }

  char buffer[SSH_CHATTER_MESSAGE_LIMIT + 1U];
  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, message, SSH_CHATTER_MESSAGE_LIMIT);
  buffer[SSH_CHATTER_MESSAGE_LIMIT] = '\0';

  ssh_channel_write(channel, buffer, strlen(buffer));
  ssh_channel_write(channel, "\r\n", 2U);
}

static void session_send_plain_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  session_send_line(ctx->channel, message);
}

static void session_send_system_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  char formatted[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(formatted, sizeof(formatted), "%s%s%s%s%s", bg, fg, bold, message, ANSI_RESET);
  session_send_line(ctx->channel, formatted);
}

static void session_send_raw_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || ctx->channel == NULL || text == NULL) {
    return;
  }

  const char *cursor = text;
  while (*cursor != '\0') {
    const char *newline = strchr(cursor, '\n');
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (newline == NULL) {
      snprintf(line, sizeof(line), "%s", cursor);
      session_send_plain_line(ctx, line);
      break;
    }

    size_t length = (size_t)(newline - cursor);
    if (length >= sizeof(line)) {
      length = sizeof(line) - 1U;
    }
    memcpy(line, cursor, length);
    line[length] = '\0';
    session_send_plain_line(ctx, line);

    cursor = newline + 1;
    if (*cursor == '\r') {
      ++cursor;
    }
    if (*cursor == '\0') {
      session_send_plain_line(ctx, "");
    }
  }
}

static void session_render_separator(session_ctx_t *ctx, const char *label) {
  if (ctx == NULL || label == NULL) {
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  char content[128];
  const size_t total_width = 56U;
  char label_buffer[64];
  snprintf(label_buffer, sizeof(label_buffer), " %s ", label);
  size_t label_len = strlen(label_buffer);
  if (label_len > total_width) {
    label_len = total_width;
    label_buffer[total_width] = '\0';
  }
  size_t remaining = total_width > label_len ? total_width - label_len : 0U;
  size_t offset = 0U;

  const char *full_dash = "─";
  const size_t full_dash_len = 3U;
  const size_t full_dash_width = 2U;
  
  const char *half_dash = "-";
  const size_t half_dash_len = 1U;
  const size_t half_dash_width = 1U;
  
  size_t filled_width = 0U;
  
  while (filled_width < remaining) {
    size_t width_left = remaining - filled_width;
  
    if (width_left >= full_dash_width) {
      if (offset + full_dash_len >= sizeof(content)) {
        break;
      }
  
      memcpy(content + offset, full_dash, full_dash_len);
      offset += full_dash_len;
      filled_width += full_dash_width;
    } else if (width_left == half_dash_width) {
      if (offset + half_dash_len >= sizeof(content)) {
        break;
      }
  
      memcpy(content + offset, half_dash, half_dash_len);
      offset += half_dash_len;
      filled_width += half_dash_width;
    } else {
      break;
    }
  }
  content[offset] = '\0';

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s╭%s%s╮%s", hl, fg, bold, label_buffer, content, ANSI_RESET);
  session_send_line(ctx->channel, line);
}

static void session_render_banner(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  static const char *kBanner[] = {
    "+====================================================+",
    "|    ____ _           _   _                         |",
    "|   / ___| |__   __ _| |_| |_ ___ _ __              |",
    "|  | |   | '_ \\ / _` | __| __/ _ \\ '__|             |",
    "|  | |___| | | | (_| | |_| ||  __/ |                |",
    "|   \\____|_| |_|\\__,_|\\__|\\__\\___|_|                |",
    "|                                                    |",
    "|   cute and tiny SSH chat written in C language.    |",
    "|   Type /help to see available commands.            |",
    "+====================================================+",
};

  for (size_t idx = 0; idx < sizeof(kBanner) / sizeof(kBanner[0]); ++idx) {
    session_send_system_line(ctx, kBanner[idx]);
  }

  char welcome[SSH_CHATTER_MESSAGE_LIMIT];
  size_t name_len = strlen(ctx->user.name);
  int welcome_padding = 47 - (int)name_len;
  if (welcome_padding < 0) {
    welcome_padding = 0;
  }
  snprintf(welcome, sizeof(welcome), "|  Welcome, %s!%*s|", ctx->user.name, welcome_padding, "");
  session_send_system_line(ctx, welcome);

  char version_line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t version_len = strlen(ctx->owner->version);
  int version_padding = 50 - (int)version_len;
  if (version_padding < 0) {
    version_padding = 0;
  }
  snprintf(version_line, sizeof(version_line), "|  %s%*s|", ctx->owner->version, version_padding, "");
  session_send_system_line(ctx, version_line);
  session_send_system_line(ctx, "+====================================================+");
  session_render_separator(ctx, "Chatroom");
}

static void session_render_prompt(session_ctx_t *ctx, bool include_separator) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  if (include_separator) {
    session_render_separator(ctx, "Input");
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  char prompt[96];
  snprintf(prompt, sizeof(prompt), "%s╰─%s%s> %s", hl, fg, bold, ANSI_RESET);
  ssh_channel_write(ctx->channel, prompt, strlen(prompt));

  if (ctx->input_length > 0U) {
    ssh_channel_write(ctx->channel, ctx->input_buffer, ctx->input_length);
  }
}

static void session_refresh_input_line(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  static const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  ssh_channel_write(ctx->channel, clear_sequence, sizeof(clear_sequence) - 1U);
  session_render_prompt(ctx, false);
}

static void session_set_input_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));

  if (text != NULL && text[0] != '\0') {
    const size_t len = strnlen(text, sizeof(ctx->input_buffer) - 1U);
    memcpy(ctx->input_buffer, text, len);
    ctx->input_buffer[len] = '\0';
    ctx->input_length = len;
  }

  session_refresh_input_line(ctx);
}

static void session_local_echo_char(session_ctx_t *ctx, char ch) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  if (ch == '\r' || ch == '\n') {
    ssh_channel_write(ctx->channel, "\r\n", 2U);
    return;
  }

  ssh_channel_write(ctx->channel, &ch, 1U);
}

static size_t session_utf8_prev_char_len(const char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return 0U;
  }

  size_t idx = length;
  while (idx > 0U) {
    --idx;
    const unsigned char byte = (unsigned char)buffer[idx];
    if ((byte & 0xC0U) != 0x80U) {
      const size_t seq_len = length - idx;
      size_t expected = 1U;
      if ((byte & 0x80U) == 0U) {
        expected = 1U;
      } else if ((byte & 0xE0U) == 0xC0U) {
        expected = 2U;
      } else if ((byte & 0xF0U) == 0xE0U) {
        expected = 3U;
      } else if ((byte & 0xF8U) == 0xF0U) {
        expected = 4U;
      } else {
        expected = 1U;
      }

      if (seq_len < expected) {
        return seq_len;
      }
      return expected;
    }
  }

  return 1U;
}

static int session_utf8_char_width(const char *bytes, size_t length) {
  if (bytes == NULL || length == 0U) {
    return 0;
  }

  mbstate_t state;
  memset(&state, 0, sizeof(state));

  wchar_t wc;
  const size_t result = mbrtowc(&wc, bytes, length, &state);
  if (result == (size_t)-1 || result == (size_t)-2) {
    return 1;
  }

  const int width = wcwidth(wc);
  if (width < 0) {
    return 1;
  }

  return width;
}

static void session_local_backspace(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->channel == NULL || ctx->input_length == 0U) {
    return;
  }

  const size_t char_len = session_utf8_prev_char_len(ctx->input_buffer, ctx->input_length);
  if (char_len == 0U || char_len > ctx->input_length) {
    return;
  }

  const size_t char_start = ctx->input_length - char_len;
  const int display_width = session_utf8_char_width(&ctx->input_buffer[char_start], char_len);

  ctx->input_length = char_start;
  ctx->input_buffer[ctx->input_length] = '\0';

  const int width = display_width > 0 ? display_width : 1;
  const char sequence[] = "\b \b";
  for (int idx = 0; idx < width; ++idx) {
    ssh_channel_write(ctx->channel, sequence, sizeof(sequence) - 1U);
  }
}

static void session_clear_input(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));
  ctx->input_history_position = -1;
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
}

static void session_history_record(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL) {
    return;
  }

  bool has_visible = false;
  for (const char *cursor = line; *cursor != '\0'; ++cursor) {
    if (!isspace((unsigned char)*cursor)) {
      has_visible = true;
      break;
    }
  }

  if (!has_visible) {
    ctx->input_history_position = -1;
    return;
  }

  if (ctx->input_history_count > 0U) {
    const size_t last_index = ctx->input_history_count - 1U;
    if (strncmp(ctx->input_history[last_index], line, sizeof(ctx->input_history[last_index])) == 0) {
      ctx->input_history_position = -1;
      return;
    }
  }

  if (ctx->input_history_count < SSH_CHATTER_INPUT_HISTORY_LIMIT) {
    snprintf(ctx->input_history[ctx->input_history_count], sizeof(ctx->input_history[0]), "%s", line);
    ++ctx->input_history_count;
  } else {
    memmove(ctx->input_history, ctx->input_history + 1,
            sizeof(ctx->input_history) - sizeof(ctx->input_history[0]));
    snprintf(ctx->input_history[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U], sizeof(ctx->input_history[0]), "%s", line);
  }

  ctx->input_history_position = -1;
  ctx->history_scroll_position = 0U;
}

static void session_history_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || direction == 0) {
    return;
  }

  ctx->history_scroll_position = 0U;

  if (ctx->input_history_count == 0U) {
    ctx->input_history_position = (int)ctx->input_history_count;
    session_set_input_text(ctx, "");
    return;
  }

  int position = ctx->input_history_position;
  if (position < 0 || position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  position += direction;
  if (position < 0) {
    position = 0;
  }
  if (position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  ctx->input_history_position = position;

  if (position == (int)ctx->input_history_count) {
    session_set_input_text(ctx, "");
  } else {
    session_set_input_text(ctx, ctx->input_history[position]);
  }
}

static void session_scrollback_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || ctx->owner == NULL || ctx->channel == NULL || direction == 0) {
    return;
  }

  chat_history_entry_t snapshot[SSH_CHATTER_HISTORY_LIMIT];
  size_t count = host_history_snapshot(ctx->owner, snapshot, SSH_CHATTER_HISTORY_LIMIT);
  if (count == 0U) {
    session_send_system_line(ctx, "No chat history available yet.");
    return;
  }

  const size_t step = SSH_CHATTER_SCROLLBACK_CHUNK > 0 ? SSH_CHATTER_SCROLLBACK_CHUNK : 1U;
  size_t position = ctx->history_scroll_position;
  size_t new_position = position;

  const size_t max_position = count > 0U ? count - 1U : 0U;

  if (direction > 0) {
    if (new_position < max_position) {
      size_t advance = step;
      if (advance > max_position - new_position) {
        advance = max_position - new_position;
      }
      new_position += advance;
    }
  } else if (direction < 0) {
    if (new_position > 0U) {
      size_t retreat = step;
      if (retreat > new_position) {
        retreat = new_position;
      }
      new_position -= retreat;
    }
  }

  bool at_boundary = (new_position == position);
  ctx->history_scroll_position = new_position;

  const size_t newest_visible = count - 1U - new_position;
  size_t chunk = step;
  if (chunk > newest_visible + 1U) {
    chunk = newest_visible + 1U;
  }
  if (chunk == 0U) {
    chunk = 1U;
  }

  const size_t oldest_visible = (newest_visible + 1U > chunk) ? (newest_visible + 1U - chunk) : 0U;

  const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  ssh_channel_write(ctx->channel, clear_sequence, sizeof(clear_sequence) - 1U);
  ssh_channel_write(ctx->channel, "\r\n", 2U);

  if (direction > 0 && at_boundary && new_position == max_position) {
    session_send_system_line(ctx, "Reached the oldest stored message.");
  } else if (direction < 0 && at_boundary && new_position == 0U) {
    session_send_system_line(ctx, "Already at the latest messages.");
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Scrollback (%zu-%zu of %zu)", oldest_visible + 1U, newest_visible + 1U, count);
  session_send_system_line(ctx, header);

  for (size_t idx = oldest_visible; idx <= newest_visible; ++idx) {
    session_send_history_entry(ctx, &snapshot[idx]);
  }

  if (new_position == 0U) {
    session_send_system_line(ctx, "End of scrollback.");
  }

  session_render_prompt(ctx, false);
}

static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch) {
  if (ctx == NULL) {
    return false;
  }

  if (!ctx->input_escape_active) {
    if (ch == 0x1b) {
      ctx->input_escape_active = true;
      ctx->input_escape_length = 0U;
      if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
        ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
      }
      return true;
    }
    return false;
  }

  if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
    ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
  }

  const char *sequence = ctx->input_escape_buffer;
  const size_t length = ctx->input_escape_length;

  if (length == 1U) {
    return true;
  }

  if (length == 2U) {
    if (sequence[1] == '[') {
      return true;
    }
    if (sequence[1] == 'k') {
      session_history_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[1] == 'j') {
      session_history_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == '[') {
    if (sequence[2] == 'A') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == 'O') {
    if (sequence[2] == 'A') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 4U && sequence[1] == '[' && sequence[3] == '~') {
    if (sequence[2] == '5') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == '6') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  const bool bracket_sequence = (length >= 2U && sequence[1] == '[');
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (bracket_sequence) {
    return true;
  }
  return ch == 0x1b;
}

static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source, const char *label,
                                              const char *message) {
  if (ctx == NULL || ctx->channel == NULL || color_source == NULL || label == NULL || message == NULL) {
    return;
  }

  const char *highlight = color_source->user_highlight_code != NULL ? color_source->user_highlight_code : "";
  const char *color = color_source->user_color_code != NULL ? color_source->user_color_code : "";
  const char *bold = color_source->user_is_bold ? ANSI_BOLD : "";

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color, label, ANSI_RESET, message);
  session_send_line(ctx->channel, line);

  if (ctx != color_source && ctx->history_scroll_position == 0U) {
    session_refresh_input_line(ctx);
  }
}

static uint64_t session_preview_hash(const char *text) {
  if (text == NULL) {
    return 0ULL;
  }

  uint64_t hash = 1469598103934665603ULL; /* FNV-1a offset basis */
  const unsigned char *bytes = (const unsigned char *)text;
  while (*bytes != '\0') {
    hash ^= (uint64_t)(*bytes++);
    hash *= 1099511628211ULL;
  }
  return hash;
}

static uint64_t session_preview_next(uint64_t *state) {
  if (state == NULL) {
    return 0ULL;
  }

  uint64_t value = *state;
  if (value == 0ULL) {
    value = 0x2545F4914F6CDD1DULL;
  }

  value ^= value >> 12;
  value ^= value << 25;
  value ^= value >> 27;
  *state = value;
  return value * 2685821657736338717ULL;
}

static size_t session_build_image_preview(const char *seed,
                                         char lines[][SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN],
                                         size_t max_lines) {
  if (seed == NULL || lines == NULL || max_lines == 0U) {
    return 0U;
  }

  const size_t rows = SSH_CHATTER_IMAGE_PREVIEW_HEIGHT < max_lines ? SSH_CHATTER_IMAGE_PREVIEW_HEIGHT : max_lines;
  const size_t columns = SSH_CHATTER_IMAGE_PREVIEW_WIDTH;
  static const char *kBlocks[] = {"█", "▓", "▒", "░", "·", " "};

  uint64_t state = session_preview_hash(seed);
  if (state == 0ULL) {
    state = 0xA0761D6478BD642FULL;
  }

  for (size_t row = 0U; row < rows; ++row) {
    char *target = lines[row];
    if (target == NULL) {
      continue;
    }

    int written = snprintf(target, SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN, "    ");
    size_t offset = 0U;
    if (written > 0) {
      offset = (size_t)written;
      if (offset >= SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN) {
        offset = SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN - 1U;
      }
    }

    for (size_t column = 0U; column < columns; ++column) {
      uint64_t value = session_preview_next(&state);
      const char *emoji = kBlocks[value % (sizeof(kBlocks) / sizeof(kBlocks[0]))];
      size_t emoji_len = strlen(emoji);
      if (offset + emoji_len >= SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN) {
        break;
      }
      memcpy(target + offset, emoji, emoji_len);
      offset += emoji_len;
    }

    target[offset] = '\0';
  }

  return rows;
}

static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry) {
  if (ctx == NULL || ctx->channel == NULL || entry == NULL) {
    return;
  }

  if (entry->is_user_message) {
    const char *highlight = entry->user_highlight_code != NULL ? entry->user_highlight_code : "";
    const char *color = entry->user_color_code != NULL ? entry->user_color_code : "";
    const char *bold = entry->user_is_bold ? ANSI_BOLD : "";

    const char *message_text = entry->message;
    char fallback[SSH_CHATTER_MESSAGE_LIMIT + 64];
    if ((message_text == NULL || message_text[0] == '\0') && entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(fallback, sizeof(fallback), "shared a %s", label);
      message_text = fallback;
    } else if (message_text == NULL) {
      message_text = "";
    }

    char header[SSH_CHATTER_MESSAGE_LIMIT + 128];
    if (entry->message_id > 0U) {
      snprintf(header, sizeof(header), "[#%" PRIu64 "] %s%s%s%s%s %s", entry->message_id, highlight, bold, color,
               entry->username, ANSI_RESET, message_text);
    } else {
      snprintf(header, sizeof(header), "%s%s%s%s%s %s", highlight, bold, color, entry->username, ANSI_RESET,
               message_text);
    }
    session_send_plain_line(ctx, header);

    char attachment_line[SSH_CHATTER_ATTACHMENT_TARGET_LEN + 64];
    if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(attachment_line, sizeof(attachment_line), "    ↳ %s: %s", label, entry->attachment_target);
      session_send_plain_line(ctx, attachment_line);
    }

    char caption_line[SSH_CHATTER_ATTACHMENT_CAPTION_LEN + 32];
    if (entry->attachment_caption[0] != '\0') {
      snprintf(caption_line, sizeof(caption_line), "    ↳ note: %s", entry->attachment_caption);
      session_send_plain_line(ctx, caption_line);
    }

    char reactions_line[SSH_CHATTER_MESSAGE_LIMIT];
    if (chat_history_entry_build_reaction_summary(entry, reactions_line, sizeof(reactions_line))) {
      char summary_line[SSH_CHATTER_MESSAGE_LIMIT + 32];
      snprintf(summary_line, sizeof(summary_line), "    ↳ reactions: %s", reactions_line);
      session_send_plain_line(ctx, summary_line);
    }

    if (entry->attachment_type == CHAT_ATTACHMENT_IMAGE && entry->message_id > 0U) {
      char hint[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(hint, sizeof(hint), "    ↳ hint: /image-to-ascii %" PRIu64 " for a preview", entry->message_id);
      session_send_plain_line(ctx, hint);
    }
  } else {
    session_send_system_line(ctx, entry->message);
  }
}

static void session_send_poll_summary(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  struct poll_snapshot {
    bool active;
    uint64_t id;
    char question[SSH_CHATTER_MESSAGE_LIMIT];
    size_t option_count;
    struct {
      char text[SSH_CHATTER_MESSAGE_LIMIT];
      uint32_t votes;
    } options[5];
  } snapshot = {0};

  pthread_mutex_lock(&host->lock);
  snapshot.active = host->poll.active;
  snapshot.id = host->poll.id;
  snapshot.option_count = host->poll.option_count;
  snprintf(snapshot.question, sizeof(snapshot.question), "%s", host->poll.question);
  for (size_t idx = 0U; idx < host->poll.option_count && idx < sizeof(snapshot.options) / sizeof(snapshot.options[0]); ++idx) {
    snprintf(snapshot.options[idx].text, sizeof(snapshot.options[idx].text), "%s", host->poll.options[idx].text);
    snapshot.options[idx].votes = host->poll.options[idx].votes;
  }
  pthread_mutex_unlock(&host->lock);

  if (!snapshot.active || snapshot.option_count == 0U) {
    session_send_system_line(ctx, "No active poll right now.");
    return;
  }

  char question_line[SSH_CHATTER_MESSAGE_LIMIT + 64];
  snprintf(question_line, sizeof(question_line), "Poll #%" PRIu64 ": %s", snapshot.id, snapshot.question);
  session_send_system_line(ctx, question_line);

  for (size_t idx = 0U; idx < snapshot.option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT + 32];
    uint32_t votes = snapshot.options[idx].votes;
    snprintf(option_line, sizeof(option_line), "  /%zu - %s (%u vote%s)", idx + 1U, snapshot.options[idx].text, votes,
             votes == 1U ? "" : "s");
    session_send_system_line(ctx, option_line);
  }

  session_send_system_line(ctx, "Vote with /1 through /5.");
}

static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length) {
  if (entry == NULL || buffer == NULL || length == 0U) {
    return false;
  }

  buffer[0] = '\0';
  bool any = false;
  size_t offset = 0U;

  for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
    uint32_t count = entry->reaction_counts[idx];
    if (count == 0U) {
      continue;
    }

    const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
    char chunk[64];
    snprintf(chunk, sizeof(chunk), "%s ×%u", descriptor->icon, count);

    size_t chunk_len = strlen(chunk);
    if (chunk_len + 1U >= length - offset) {
      break;
    }

    if (any) {
      buffer[offset++] = ' ';
    }
    memcpy(buffer + offset, chunk, chunk_len);
    offset += chunk_len;
    buffer[offset] = '\0';
    any = true;
  }

  return any;
}

static const char *chat_attachment_type_label(chat_attachment_type_t type) {
  switch (type) {
  case CHAT_ATTACHMENT_IMAGE:
    return "image";
  case CHAT_ATTACHMENT_VIDEO:
    return "video";
  case CHAT_ATTACHMENT_AUDIO:
    return "audio";
  case CHAT_ATTACHMENT_FILE:
    return "file";
  case CHAT_ATTACHMENT_NONE:
  default:
    return "attachment";
  }
}

static void session_send_history(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL || ctx->channel == NULL) {
    return;
  }

  chat_history_entry_t snapshot[SSH_CHATTER_HISTORY_LIMIT];
  size_t count = host_history_snapshot(ctx->owner, snapshot, SSH_CHATTER_HISTORY_LIMIT);
  if (count == 0U) {
    return;
  }

  size_t visible = count;
  if (visible > SSH_CHATTER_SCROLLBACK_CHUNK) {
    visible = SSH_CHATTER_SCROLLBACK_CHUNK;
  }

  const size_t start = (count > visible) ? (count - visible) : 0U;

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  if (count > visible) {
    snprintf(header, sizeof(header), "Recent activity (last %zu of %zu messages):", visible, count);
  } else {
    snprintf(header, sizeof(header), "Recent activity (last %zu message%s):", visible, visible == 1U ? "" : "s");
  }
  session_render_separator(ctx, "Recent activity");
  session_send_system_line(ctx, header);

  for (size_t idx = start; idx < count; ++idx) {
    session_send_history_entry(ctx, &snapshot[idx]);
  }

  session_send_system_line(ctx, "Use the Up/Down arrow keys to browse stored chat history.");
  session_render_separator(ctx, "Chatroom");
  ctx->history_scroll_position = 0U;
}

static bool session_handle_service_request(ssh_message message) {
  if (message == NULL) {
    return false;
  }

  const char *service = ssh_message_service_service(message);
  if (service == NULL) {
    return false;
  }

  if (strcmp(service, "ssh-userauth") == 0 || strcmp(service, "ssh-connection") == 0) {
    ssh_message_service_reply_success(message);
    return true;
  }

  return false;
}

static int session_authenticate(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool authenticated = false;

  while (!authenticated && (message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    switch (message_type) {
      case SSH_REQUEST_SERVICE:
        if (!session_handle_service_request(message)) {
          ssh_message_reply_default(message);
        }
        break;
      case SSH_REQUEST_AUTH:
        {
          const char *username = ssh_message_auth_user(message);
          if (username != NULL && username[0] != '\0') {
            snprintf(ctx->user.name, sizeof(ctx->user.name), "%.*s", SSH_CHATTER_USERNAME_LEN - 1, username);
          }
        }
        ssh_message_auth_reply_success(message, 0);
        authenticated = true;
        break;
      default:
        ssh_message_reply_default(message);
        break;
    }
    ssh_message_free(message);
  }

  return authenticated ? 0 : -1;
}

static int session_accept_channel(session_ctx_t *ctx) {
  ssh_message message = NULL;

  while ((message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    if (message_type == SSH_REQUEST_SERVICE) {
      if (!session_handle_service_request(message)) {
        ssh_message_reply_default(message);
      }
      ssh_message_free(message);
      continue;
    }

    if (message_type == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
      ssh_channel channel = ssh_message_channel_request_open_reply_accept(message);
      if (channel == NULL) {
        accept_channel_fn_t accept_channel = resolve_accept_channel_fn();
        if (accept_channel != NULL) {
          channel = ssh_channel_new(ctx->session);
          if (channel != NULL) {
            if (accept_channel(message, channel) != SSH_OK) {
              ssh_channel_free(channel);
              channel = NULL;
            }
          }
        }
      }

      if (channel != NULL) {
        ctx->channel = channel;
        ssh_message_free(message);
        break;
      }

      ssh_message_reply_default(message);
      ssh_message_free(message);
      continue;
    }

    ssh_message_reply_default(message);
    ssh_message_free(message);
  }

  return ctx->channel != NULL ? 0 : -1;
}

static int session_prepare_shell(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool shell_ready = false;

  while (!shell_ready && (message = ssh_message_get(ctx->session)) != NULL) {
    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
      const int subtype = ssh_message_subtype(message);
      if (subtype == SSH_CHANNEL_REQUEST_PTY || subtype == SSH_CHANNEL_REQUEST_SHELL) {
        ssh_message_channel_request_reply_success(message);
        if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
          shell_ready = true;
        }
      } else {
        ssh_message_reply_default(message);
      }
    } else {
      ssh_message_reply_default(message);
    }
    ssh_message_free(message);
  }

  return shell_ready ? 0 : -1;
}

static void session_print_help(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_send_system_line(ctx, "Available commands:");
  session_send_system_line(ctx, "/help                 - show this message");
  session_send_system_line(ctx, "/exit                 - leave the chat");
  session_send_system_line(ctx, "/nick <name>          - change your display name");
  session_send_system_line(ctx, "/pm <username> <message> - send a private message");
  session_send_system_line(ctx, "/motd                - view the message of the day");
  session_send_system_line(ctx, "/users               - announce the number of connected users");
  session_send_system_line(ctx, "/search <text>       - search for users whose name matches text");
  session_send_system_line(ctx, "/image <url> [caption] - share an image link");
  session_send_system_line(ctx, "/video <url> [caption] - share a video link");
  session_send_system_line(ctx, "/audio <url> [caption] - share an audio clip");
  session_send_system_line(ctx, "/files <url> [caption] - share a downloadable file");
  session_send_system_line(ctx, "/image-to-ascii <id> - render a 48x48 ASCII preview of an image message");
  session_send_system_line(ctx, "Up/Down arrows           - scroll recent chat history");
  session_send_system_line(ctx, "/color (text;highlight[;bold]) - style your handle");
  session_send_system_line(ctx,
                           "/systemcolor (fg;background[;highlight][;bold]) - style the interface (third value may "
                           "be highlight or bold; use /systemcolor reset to restore defaults)");
  session_send_system_line(ctx, "/palette <name>        - apply a predefined interface palette (/palette list)");
  session_send_system_line(ctx, "/today               - discover today's function (once per day)");
  session_send_system_line(ctx, "/date <timezone>     - view the server time in another timezone");
  session_send_system_line(ctx, "/os <name>           - record the operating system you use");
  session_send_system_line(ctx, "/getos <username>    - look up someone else's recorded operating system");
  session_send_system_line(ctx, "/pair                - list users sharing your recorded OS");
  session_send_system_line(ctx, "/connected           - privately list everyone connected");
  session_send_system_line(ctx, "/poll <question>|<option...> - start or view a poll");
  session_send_system_line(ctx, "/poke <username>      - send a bell to call a user");
  session_send_system_line(ctx, "/ban <username>       - ban a user (operator only)");
  session_send_system_line(ctx, "/pardon <user|ip>     - remove a ban (operator only)");
  session_send_system_line(ctx,
                           "/good|/sad|/cool|/angry|/checked|/love|/wtf <id> - react to a message by number");
  session_send_system_line(ctx, "/1 .. /5             - vote for an option in the active poll");
  session_send_system_line(ctx, "Regular messages are shared with everyone.");
}

static bool session_line_is_exit_command(const char *line) {
  if (line == NULL) {
    return false;
  }

  if (strncmp(line, "/exit", 5) != 0) {
    return false;
  }

  const char trailing = line[5];
  if (trailing == '\0') {
    return true;
  }

  if (!isspace((unsigned char)trailing)) {
    return false;
  }

  for (size_t idx = 6U; line[idx] != '\0'; ++idx) {
    if (!isspace((unsigned char)line[idx])) {
      return false;
    }
  }

  return true;
}

static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL) {
    return;
  }

  if (session_line_is_exit_command(line)) {
    session_handle_exit(ctx);
    return;
  }

  char reminder[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(reminder, sizeof(reminder), "The username '%s' is already in use.", ctx->user.name);
  session_send_system_line(ctx, reminder);
  session_send_system_line(ctx,
                           "Reconnect with a different username by running: ssh newname@<server> (or ssh -l newname <server>)");
  session_send_system_line(ctx, "Type /exit to quit.");
}

static void session_process_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL || line[0] == '\0') {
    return;
  }

  char normalized[SSH_CHATTER_MAX_INPUT_LEN];
  snprintf(normalized, sizeof(normalized), "%s", line);
  session_normalize_newlines(normalized);

  if (normalized[0] == '\0') {
    return;
  }

  printf("[%s] %s\n", ctx->user.name, normalized);

  const struct timespec tiny_delay = {.tv_sec = 0, .tv_nsec = 5000000L};
  nanosleep(&tiny_delay, NULL);

  if (ctx->username_conflict) {
    session_handle_username_conflict_input(ctx, normalized);
    return;
  }

  if (normalized[0] == '/') {
    session_dispatch_command(ctx, normalized);
    return;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  bool allow_message = true;
  if (ctx->has_last_message_time) {
    time_t sec_delta = now.tv_sec - ctx->last_message_time.tv_sec;
    long nsec_delta = now.tv_nsec - ctx->last_message_time.tv_nsec;
    if (nsec_delta < 0L) {
      --sec_delta;
    }
    if (sec_delta < 1) {
      allow_message = false;
    }
  }

  if (!allow_message) {
    session_send_system_line(ctx, "Please wait at least one second before sending another message.");
    return;
  }

  ctx->last_message_time = now;
  ctx->has_last_message_time = true;

  chat_history_entry_t entry = {0};
  if (!host_history_record_user(ctx->owner, ctx, normalized, &entry)) {
    return;
  }

  session_send_history_entry(ctx, &entry);
  chat_room_broadcast_entry(&ctx->owner->room, &entry, ctx);
}

static void session_handle_ban(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to ban users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    char not_found[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, not_found);
    return;
  }

  if (target->user.is_lan_operator) {
    session_send_system_line(ctx, "LAN operators cannot be banned.");
    return;
  }

  const char *target_ip = target->client_ip[0] != '\0' ? target->client_ip : "";
  if (!host_add_ban_entry(ctx->owner, target->user.name, target_ip)) {
    session_send_system_line(ctx, "Unable to add ban entry (list full?).");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* %s has been banned by %s", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
  session_send_system_line(ctx, "Ban applied.");
  printf("[ban] %s banned %s (%s)\n", ctx->user.name, target->user.name, target_ip[0] != '\0' ? target_ip : "unknown");

  if (target->channel != NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "You have been banned by %s.", ctx->user.name);
    session_send_system_line(target, message);
    target->should_exit = true;
    ssh_channel_send_eof(target->channel);
    ssh_channel_close(target->channel);
  }
}

static void session_handle_poke(session_ctx_t *ctx, const char *arguments) {
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /poke <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, arguments);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", arguments);
    session_send_system_line(ctx, message);
    return;
  }

  printf("[poke] %s pokes %s\n", ctx->user.name, target->user.name);
  ssh_channel_write(target->channel, "\a", 1U);
  session_send_system_line(ctx, "Poke sent.");
}

static void session_handle_pm(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /pm <username> <message>";

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Private messages are unavailable right now.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *cursor = working;
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  *cursor = '\0';
  char *message = cursor + 1;
  while (*message != '\0' && isspace((unsigned char)*message)) {
    ++message;
  }

  if (*message == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%.*s", (int)sizeof(target_name) - 1, working);

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    char not_found[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, not_found);
    return;
  }

  printf("[pm] %s -> %s: %s\n", ctx->user.name, target->user.name, message);

  char to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_target_label, sizeof(to_target_label), "%s -> you", ctx->user.name);
  session_send_private_message_line(target, ctx, to_target_label, message);

  char to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_sender_label, sizeof(to_sender_label), "you -> %s", target->user.name);
  session_send_private_message_line(ctx, ctx, to_sender_label, message);
}

static bool username_contains(const char *username, const char *needle) {
  if (username == NULL || needle == NULL) {
    return false;
  }

  const size_t needle_len = strlen(needle);
  if (needle_len == 0U) {
    return false;
  }

  const size_t name_len = strlen(username);
  if (needle_len > name_len) {
    return false;
  }

  for (size_t offset = 0U; offset + needle_len <= name_len; ++offset) {
    bool match = true;
    for (size_t idx = 0U; idx < needle_len; ++idx) {
      const unsigned char user_ch = (unsigned char)username[offset + idx];
      const unsigned char needle_ch = (unsigned char)needle[idx];
      if (tolower(user_ch) != tolower(needle_ch)) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }

  return false;
}

static void session_handle_search(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Search is unavailable at the moment.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char query[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(query, sizeof(query), "%s", arguments);
  trim_whitespace_inplace(query);

  if (query[0] == '\0') {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char matches[SSH_CHATTER_MAX_USERS][SSH_CHATTER_USERNAME_LEN];
  size_t match_count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL) {
      continue;
    }
    if (username_contains(member->user.name, query)) {
      if (match_count < SSH_CHATTER_MAX_USERS) {
        snprintf(matches[match_count], sizeof(matches[match_count]), "%s", member->user.name);
        ++match_count;
      }
    }
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  if (match_count == 0U) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    char display_query[64];
    size_t copy_len = strnlen(query, sizeof(display_query) - 1U);
    memcpy(display_query, query, copy_len);
    display_query[copy_len] = '\0';
    snprintf(message, sizeof(message), "No users matching '%s'.", display_query);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Matching users (%zu):", match_count);
  session_send_system_line(ctx, header);

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  line[0] = '\0';
  size_t offset = 0U;

  for (size_t idx = 0U; idx < match_count; ++idx) {
    const char *name = matches[idx];
    const size_t name_len = strnlen(name, sizeof(matches[idx]));
    const size_t prefix_len = (offset == 0U) ? 0U : 2U;

    if (offset + prefix_len + name_len >= sizeof(line)) {
      if (offset > 0U) {
        session_send_system_line(ctx, line);
        line[0] = '\0';
        offset = 0U;
      }
    }

    if (offset == 0U) {
      int written = snprintf(line, sizeof(line), "%s", name);
      if (written < 0) {
        line[0] = '\0';
        offset = 0U;
      } else if ((size_t)written >= sizeof(line)) {
        offset = sizeof(line) - 1U;
      } else {
        offset = (size_t)written;
      }
    } else {
      int written = snprintf(line + offset, sizeof(line) - offset, ", %s", name);
      if (written < 0) {
        continue;
      }
      if ((size_t)written >= sizeof(line) - offset) {
        session_send_system_line(ctx, line);
        int restart = snprintf(line, sizeof(line), "%s", name);
        if (restart < 0) {
          line[0] = '\0';
          offset = 0U;
        } else if ((size_t)restart >= sizeof(line)) {
          offset = sizeof(line) - 1U;
        } else {
          offset = (size_t)restart;
        }
      } else {
        offset += (size_t)written;
      }
    }
  }

  if (offset > 0U) {
    session_send_system_line(ctx, line);
  }
}

static void session_handle_image(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /image <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Image URL is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared an image");
  entry.attachment_type = CHAT_ATTACHMENT_IMAGE;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record image message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
}

static void session_handle_video(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /video <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Video link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared a video");
  entry.attachment_type = CHAT_ATTACHMENT_VIDEO;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record video message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
}

static void session_handle_audio(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /audio <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Audio link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared an audio clip");
  entry.attachment_type = CHAT_ATTACHMENT_AUDIO;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record audio message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
}

static void session_handle_files(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /files <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "File link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared a file");
  entry.attachment_type = CHAT_ATTACHMENT_FILE;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record file message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
}

static void session_handle_reaction(session_ctx_t *ctx, size_t reaction_index, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL || reaction_index >= SSH_CHATTER_REACTION_KIND_COUNT) {
    return;
  }

  const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[reaction_index];

  char usage[64];
  snprintf(usage, sizeof(usage), "Usage: /%s <message-id>", descriptor->command);

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[64];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *endptr = NULL;
  unsigned long long parsed = strtoull(working, &endptr, 10);
  if (parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, usage);
    return;
  }

  uint64_t message_id = (uint64_t)parsed;
  chat_history_entry_t updated = {0};
  if (!host_history_apply_reaction(ctx->owner, message_id, reaction_index, &updated)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Message #%" PRIu64 " was not found or cannot be reacted to.", message_id);
    session_send_system_line(ctx, message);
    return;
  }

  char confirmation[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(confirmation, sizeof(confirmation), "Added %s %s to message #%" PRIu64 ".", descriptor->icon, descriptor->label,
           message_id);
  session_send_system_line(ctx, confirmation);
  chat_room_broadcast_reaction_update(ctx->owner, &updated);
}

static void session_handle_usercount(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  size_t count = 0U;
  pthread_mutex_lock(&ctx->owner->room.lock);
  count = ctx->owner->room.member_count;
  pthread_mutex_unlock(&ctx->owner->room.lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "There %s currently %zu user%s connected.",
           count == 1U ? "is" : "are", count, count == 1U ? "" : "s");

  host_history_record_system(ctx->owner, message);
  chat_room_broadcast(&ctx->owner->room, message, NULL);
}

static void session_handle_image_to_ascii(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /image-to-ascii <message-id>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[64];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  errno = 0;
  char *endptr = NULL;
  unsigned long long parsed = strtoull(working, &endptr, 10);
  if (errno != 0 || parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  uint64_t message_id = (uint64_t)parsed;
  session_send_system_line(ctx, "trying to render...");

  chat_history_entry_t entry = {0};
  if (!host_history_find_entry_by_id(ctx->owner, message_id, &entry)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Message #%" PRIu64 " was not found.", message_id);
    session_send_system_line(ctx, message);
    return;
  }

  if (entry.attachment_type != CHAT_ATTACHMENT_IMAGE || entry.attachment_target[0] == '\0') {
    session_send_system_line(ctx, "That message does not include an image attachment.");
    return;
  }

  char preview_lines[SSH_CHATTER_IMAGE_PREVIEW_HEIGHT][SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN];
  size_t preview_count =
      session_build_image_preview(entry.attachment_target, preview_lines, SSH_CHATTER_IMAGE_PREVIEW_HEIGHT);
  if (preview_count == 0U) {
    session_send_system_line(ctx, "Unable to build an ASCII preview right now.");
    return;
  }

  session_send_plain_line(ctx, "ASCII preview:");
  for (size_t idx = 0U; idx < preview_count; ++idx) {
    session_send_plain_line(ctx, preview_lines[idx]);
  }
}

static void session_handle_today(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  time_t now = time(NULL);
  struct tm tm_now;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
  if (localtime_r(&now, &tm_now) == NULL) {
    session_send_system_line(ctx, "Unable to determine local time.");
    return;
  }
#else
  struct tm *tmp = localtime(&now);
  if (tmp == NULL) {
    session_send_system_line(ctx, "Unable to determine local time.");
    return;
  }
  tm_now = *tmp;
#endif

  int year = tm_now.tm_year + 1900;
  int yday = tm_now.tm_yday;

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Unable to track today's function right now.");
    return;
  }

  if (!host->random_seeded) {
    unsigned seed = (unsigned int)(time(NULL) ^ getpid() ^ (unsigned int)pthread_self());
    rand_r(&seed);
    host->random_seeded = true;
  }

  const char *chosen = NULL;
  bool already = false;
  if (pref->daily_year == year && pref->daily_yday == yday && pref->daily_function[0] != '\0') {
    chosen = pref->daily_function;
    already = true;
  } else {
    const size_t function_count = sizeof(DAILY_FUNCTIONS) / sizeof(DAILY_FUNCTIONS[0]);
    if (function_count == 0U) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "No functions available today.");
      return;
    }
    size_t index = (size_t)(rand() % function_count);
    chosen = DAILY_FUNCTIONS[index];
    pref->daily_year = year;
    pref->daily_yday = yday;
    snprintf(pref->daily_function, sizeof(pref->daily_function), "%s", chosen);
  }

  ctx->daily_year = pref->daily_year;
  ctx->daily_yday = pref->daily_yday;
  snprintf(ctx->daily_function, sizeof(ctx->daily_function), "%s", chosen);

  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  if (already) {
    snprintf(message, sizeof(message), "You've already discovered today's function: %s", chosen);
  } else {
    snprintf(message, sizeof(message), "Today's function for you is: %s", chosen);
  }
  session_send_system_line(ctx, message);
}

static void session_handle_date(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /date <Area/Location>";

  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char sanitized[PATH_MAX];
  if (!timezone_sanitize_identifier(working, sanitized, sizeof(sanitized))) {
    session_send_system_line(ctx, "Timezone names may only include letters, numbers, '/', '_', '-', '+', or '.'.");
    return;
  }

  char resolved[PATH_MAX];
  if (!timezone_resolve_identifier(sanitized, resolved, sizeof(resolved))) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown timezone '%.128s'.", working);
    session_send_system_line(ctx, message);
    return;
  }

  const char *previous_tz = getenv("TZ");
  char previous_copy[PATH_MAX];
  bool had_previous = false;
  if (previous_tz != NULL) {
    int prev_written = snprintf(previous_copy, sizeof(previous_copy), "%s", previous_tz);
    if (prev_written >= 0 && (size_t)prev_written < sizeof(previous_copy)) {
      had_previous = true;
    }
  }

  bool tz_applied = false;

  if (setenv("TZ", resolved, 1) != 0) {
    session_send_system_line(ctx, "Unable to adjust timezone right now.");
    return;
  }

  tzset();
  tz_applied = true;

  time_t now = time(NULL);
  if (now == (time_t)-1) {
    session_send_system_line(ctx, "Unable to determine current time.");
    goto cleanup;
  }

  struct tm tm_now;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
  if (localtime_r(&now, &tm_now) == NULL) {
    session_send_system_line(ctx, "Unable to compute the requested local time.");
    goto cleanup;
  }
#else
  struct tm *tmp = localtime(&now);
  if (tmp == NULL) {
    session_send_system_line(ctx, "Unable to compute the requested local time.");
    goto cleanup;
  }
  tm_now = *tmp;
#endif

  char formatted[128];
  if (strftime(formatted, sizeof(formatted), "%Y-%m-%d %H:%M:%S %Z (UTC%z)", &tm_now) == 0) {
    session_send_system_line(ctx, "Unable to format the requested time.");
    goto cleanup;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%.128s -> %s", resolved, formatted);
  session_send_system_line(ctx, message);

cleanup:
  if (tz_applied) {
    if (had_previous) {
      setenv("TZ", previous_copy, 1);
    } else {
      unsetenv("TZ");
    }
    tzset();
  }
}

static void session_handle_os(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage =
      "Usage: /os <windows|macos|linux|freebsd|ios|android|watchos|solaris|openbsd|netbsd|dragonflybsd|reactos|tyzen>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_OS_NAME_LEN];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  for (size_t idx = 0U; working[idx] != '\0'; ++idx) {
    working[idx] = (char)tolower((unsigned char)working[idx]);
  }

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(working);
  if (descriptor == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  snprintf(ctx->os_name, sizeof(ctx->os_name), "%s", descriptor->name);
  host_store_user_os(ctx->owner, ctx);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Recorded your operating system as %s.", descriptor->display);
  session_send_system_line(ctx, message);
}

static void session_handle_getos(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /getos <username>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char target[SSH_CHATTER_USERNAME_LEN];
  snprintf(target, sizeof(target), "%s", arguments);
  trim_whitespace_inplace(target);
  if (target[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char os_buffer[SSH_CHATTER_OS_NAME_LEN];
  if (!host_lookup_user_os(ctx->owner, target, os_buffer, sizeof(os_buffer))) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No operating system is recorded for %s.", target);
    session_send_system_line(ctx, message);
    return;
  }

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(os_buffer);
  const char *display = descriptor != NULL ? descriptor->display : os_buffer;

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%s reports using %s.", target, display);
  session_send_system_line(ctx, message);
}

static void session_handle_pair(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (ctx->os_name[0] == '\0') {
    session_send_system_line(ctx, "Set your operating system first with /os <name>.");
    return;
  }

  char matches[SSH_CHATTER_MESSAGE_LIMIT];
  matches[0] = '\0';
  size_t offset = 0U;
  size_t match_count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL || member == ctx) {
      continue;
    }
    if (member->os_name[0] == '\0') {
      continue;
    }
    if (strcasecmp(member->os_name, ctx->os_name) != 0) {
      continue;
    }

    size_t name_len = strnlen(member->user.name, sizeof(member->user.name));
    const size_t prefix = match_count == 0U ? 0U : 2U;
    if (offset + prefix + name_len >= sizeof(matches)) {
      break;
    }
    if (match_count > 0U) {
      matches[offset++] = ',';
      matches[offset++] = ' ';
    }
    memcpy(matches + offset, member->user.name, name_len);
    offset += name_len;
    matches[offset] = '\0';
    ++match_count;
  }

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(ctx->os_name);
  const char *display = descriptor != NULL ? descriptor->display : ctx->os_name;

  if (match_count == 0U) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No connected users currently share your %s setup.", display);
    session_send_system_line(ctx, message);
    pthread_mutex_unlock(&ctx->owner->room.lock);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Users sharing your %s setup:", display);
  session_send_system_line(ctx, header);
  session_send_system_line(ctx, matches);
  pthread_mutex_unlock(&ctx->owner->room.lock);
}

static void session_handle_connected(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  char buffer[SSH_CHATTER_MESSAGE_LIMIT];
  size_t offset = 0U;
  size_t count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL) {
      continue;
    }

    const size_t prefix = count == 0U ? 0U : 2U;
    size_t name_len = strnlen(member->user.name, sizeof(member->user.name));
    if (offset + prefix + name_len >= sizeof(buffer)) {
      break;
    }
    if (count > 0U) {
      buffer[offset++] = ',';
      buffer[offset++] = ' ';
    }
    memcpy(buffer + offset, member->user.name, name_len);
    offset += name_len;
    buffer[offset] = '\0';
    ++count;
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Connected users (%zu):", count);
  session_send_system_line(ctx, header);
  if (count > 0U) {
    session_send_system_line(ctx, buffer);
  }
}

static void session_handle_poll(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage =
      "Usage: /poll <question>|<option1>|<option2>[|option3][|option4][|option5] or /poll to view current poll";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_poll_summary(ctx);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_poll_summary(ctx);
    return;
  }

  char *tokens[1 + 5];
  size_t token_count = 0U;
  char *cursor = working;
  while (cursor != NULL && token_count < sizeof(tokens) / sizeof(tokens[0])) {
    char *next = strchr(cursor, '|');
    if (next != NULL) {
      *next = '\0';
    }
    trim_whitespace_inplace(cursor);
    tokens[token_count++] = cursor;
    cursor = next != NULL ? next + 1 : NULL;
  }

  if (token_count < 3U) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  size_t option_count = token_count - 1U;
  if (option_count > 5U) {
    option_count = 5U;
  }

  for (size_t idx = 1U; idx <= option_count; ++idx) {
    if (tokens[idx][0] == '\0') {
      session_send_system_line(ctx, "Poll options cannot be empty.");
      return;
    }
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  if (host->poll.id == UINT64_MAX) {
    host->poll.id = 0U;
  }
  host->poll.id += 1U;
  host->poll.active = true;
  host->poll.option_count = option_count;
  snprintf(host->poll.question, sizeof(host->poll.question), "%s", tokens[0]);
  for (size_t idx = 0U; idx < option_count; ++idx) {
    snprintf(host->poll.options[idx].text, sizeof(host->poll.options[idx].text), "%s", tokens[idx + 1U]);
    host->poll.options[idx].votes = 0U;
  }
  for (size_t idx = option_count; idx < sizeof(host->poll.options) / sizeof(host->poll.options[0]); ++idx) {
    host->poll.options[idx].text[0] = '\0';
    host->poll.options[idx].votes = 0U;
  }
  pthread_mutex_unlock(&host->lock);

  char announce[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(announce, sizeof(announce), "* %s started poll #%" PRIu64 ": %s", ctx->user.name, host->poll.id, tokens[0]);
  chat_room_broadcast(&host->room, announce, NULL);

  for (size_t idx = 0U; idx < option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(option_line, sizeof(option_line), "  /%zu - %s", idx + 1U, tokens[idx + 1U]);
    chat_room_broadcast(&host->room, option_line, NULL);
  }

  session_send_system_line(ctx, "Poll created successfully.");
  session_send_poll_summary(ctx);
}

static void session_handle_vote(session_ctx_t *ctx, size_t option_index) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  if (!host->poll.active || option_index >= host->poll.option_count) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "There is no active poll for that choice.");
    return;
  }

  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Unable to record your vote right now.");
    return;
  }

  if (pref->last_poll_id == host->poll.id && pref->last_poll_choice == (int)option_index) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "You have already voted for that option.");
    return;
  }

  if (pref->last_poll_id == host->poll.id && pref->last_poll_choice >= 0 &&
      (size_t)pref->last_poll_choice < host->poll.option_count) {
    if (host->poll.options[pref->last_poll_choice].votes > 0U) {
      host->poll.options[pref->last_poll_choice].votes -= 1U;
    }
  }

  host->poll.options[option_index].votes += 1U;
  pref->last_poll_id = host->poll.id;
  pref->last_poll_choice = (int)option_index;
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Vote recorded for option /%zu.", option_index + 1U);
  session_send_system_line(ctx, message);
  session_send_poll_summary(ctx);
}

static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count) {
  if (working == NULL || tokens == NULL || token_count == NULL) {
    return false;
  }

  *token_count = 0U;
  bool extra_tokens = false;
  char *cursor = working;
  while (cursor != NULL) {
    char *next = strchr(cursor, ';');
    if (next != NULL) {
      *next = '\0';
    }

    trim_whitespace_inplace(cursor);
    if (cursor[0] == '\0') {
      return false;
    }

    if (*token_count < max_tokens) {
      tokens[*token_count] = cursor;
      ++(*token_count);
    } else if (cursor[0] != '\0') {
      extra_tokens = true;
    }

    if (next == NULL) {
      break;
    }

    cursor = next + 1;
    if (cursor[0] == '\0') {
      extra_tokens = true;
      break;
    }
  }

  return !extra_tokens;
}

static void session_handle_color(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  bool had_parentheses = false;
  if (working[0] == '(') {
    had_parentheses = true;
    memmove(working, working + 1, strlen(working));
    trim_whitespace_inplace(working);
  }

  if (had_parentheses) {
    size_t len = strlen(working);
    if (len == 0U || working[len - 1U] != ')') {
      session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
      return;
    }
    working[len - 1U] = '\0';
    trim_whitespace_inplace(working);
  }

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char *tokens[3] = {0};
  size_t token_count = 0U;
  if (!session_parse_color_arguments(working, tokens, 3U, &token_count) || token_count < 2U) {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  const char *text_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), tokens[0]);
  if (text_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown text color '%s'.", tokens[0]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                tokens[1]);
  if (highlight_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown highlight color '%s'.", tokens[1]);
    session_send_system_line(ctx, message);
    return;
  }

  bool is_bold = false;
  if (token_count == 3U) {
    if (!parse_bool_token(tokens[2], &is_bold)) {
      session_send_system_line(ctx, "The third value must describe bold (ex: bold, true, normal).");
      return;
    }
  }

  ctx->user_color_code = text_code;
  ctx->user_highlight_code = highlight_code;
  ctx->user_is_bold = is_bold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", tokens[0]);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", tokens[1]);

  char info[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(info, sizeof(info), "Handle colors updated: text=%s highlight=%s bold=%s", tokens[0], tokens[1],
           is_bold ? "on" : "off");
  session_send_system_line(ctx, info);

  const char *bold_code = is_bold ? ANSI_BOLD : "";
  char preview[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(preview, sizeof(preview), "%s%s%s[%s] preview%s", highlight_code, bold_code, text_code, ctx->user.name,
           ANSI_RESET);
  session_send_line(ctx->channel, preview);

  if (ctx->owner != NULL) {
    host_store_user_theme(ctx->owner, ctx);
  }
}

static void session_handle_motd(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  char motd[sizeof(ctx->owner->motd)];

  pthread_mutex_lock(&ctx->owner->lock);
  snprintf(motd, sizeof(motd), "%s", ctx->owner->motd);
  pthread_mutex_unlock(&ctx->owner->lock);

  if (motd[0] == '\0') {
    session_send_system_line(ctx, "No message of the day is configured.");
    return;
  }

  session_send_raw_text(ctx, motd);
}

static void session_handle_system_color(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage =
      "Usage: /systemcolor (fg;background[;highlight][;bold]) or /systemcolor reset - third value may be highlight or "
      "bold.";

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  bool had_parentheses = false;
  if (working[0] == '(') {
    had_parentheses = true;
    memmove(working, working + 1, strlen(working));
    trim_whitespace_inplace(working);
  }

  if (had_parentheses) {
    size_t len = strlen(working);
    if (len == 0U || working[len - 1U] != ')') {
      session_send_system_line(ctx, kUsage);
      return;
    }
    working[len - 1U] = '\0';
    trim_whitespace_inplace(working);
  }

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (strcasecmp(working, "reset") == 0) {
    session_apply_system_theme_defaults(ctx);
    session_send_system_line(ctx, "System colors reset to defaults.");
    session_render_separator(ctx, "Chatroom");
    session_render_prompt(ctx, true);
    if (ctx->owner != NULL) {
      host_store_system_theme(ctx->owner, ctx);
    }
    return;
  }

  char *tokens[4] = {0};
  size_t token_count = 0U;
  if (!session_parse_color_arguments(working, tokens, 4U, &token_count) || token_count < 2U) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  const char *fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), tokens[0]);
  if (fg_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown foreground color '%s'.", tokens[0]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *bg_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                          sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), tokens[1]);
  if (bg_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown background color '%s'.", tokens[1]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *highlight_code = ctx->system_highlight_code;
  bool highlight_updated = false;
  bool is_bold = ctx->system_is_bold;
  if (token_count >= 3U) {
    bool bool_value = false;
    if (parse_bool_token(tokens[2], &bool_value)) {
      if (token_count > 3U) {
        session_send_system_line(ctx, kUsage);
        return;
      }
      is_bold = bool_value;
    } else {
      highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                         sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), tokens[2]);
      if (highlight_code == NULL) {
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(message, sizeof(message), "Unknown highlight color '%s'.", tokens[2]);
        session_send_system_line(ctx, message);
        return;
      }
      highlight_updated = true;

      if (token_count == 4U) {
        if (!parse_bool_token(tokens[3], &bool_value)) {
          session_send_system_line(ctx, "The last value must describe bold (ex: bold, true, normal).");
          return;
        }
        is_bold = bool_value;
      }
    }
  }

  ctx->system_fg_code = fg_code;
  ctx->system_bg_code = bg_code;
  ctx->system_highlight_code = highlight_code;
  ctx->system_is_bold = is_bold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", tokens[0]);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", tokens[1]);
  if (highlight_updated) {
    snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", tokens[2]);
  }

  session_send_system_line(ctx, "System colors updated.");
  session_render_separator(ctx, "Chatroom");
  session_render_prompt(ctx, true);
  if (ctx->owner != NULL) {
    host_store_system_theme(ctx->owner, ctx);
  }
}

static void session_handle_palette(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /palette <name> (try /palette list)");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0' || strcasecmp(working, "list") == 0) {
    session_send_system_line(ctx, "Available palettes:");
    for (size_t idx = 0U; idx < sizeof(PALETTE_DEFINITIONS) / sizeof(PALETTE_DEFINITIONS[0]); ++idx) {
      const palette_descriptor_t *descriptor = &PALETTE_DEFINITIONS[idx];
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "  %s - %s", descriptor->name, descriptor->description);
      session_send_system_line(ctx, line);
    }
    session_send_system_line(ctx, "Apply a palette with /palette <name>.");
    return;
  }

  const palette_descriptor_t *descriptor = palette_find_descriptor(working);
  if (descriptor == NULL) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "Unknown palette '%.32s'. Use /palette list to see options.", working);
    session_send_system_line(ctx, line);
    return;
  }

  if (!palette_apply_to_session(ctx, descriptor)) {
    session_send_system_line(ctx, "Unable to apply that palette right now.");
    return;
  }

  char info[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(info, sizeof(info), "Palette '%s' applied - %s", descriptor->name, descriptor->description);
  session_send_system_line(ctx, info);
  session_render_separator(ctx, "Chatroom");
  session_render_prompt(ctx, true);

  if (ctx->owner != NULL) {
    host_store_user_theme(ctx->owner, ctx);
    host_store_system_theme(ctx->owner, ctx);
  }
}

static void session_handle_nick(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /nick <name>");
    return;
  }

  char new_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(new_name, sizeof(new_name), "%s", arguments);
  trim_whitespace_inplace(new_name);

  if (new_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /nick <name>");
    return;
  }

  for (size_t idx = 0; new_name[idx] != '\0'; ++idx) {
    const unsigned char ch = (unsigned char)new_name[idx];
    if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '.')) {
      session_send_system_line(ctx, "Names may only contain letters, numbers, '.', '-', or '_'.");
      return;
    }
  }

  if (host_is_username_banned(ctx->owner, new_name)) {
    session_send_system_line(ctx, "That name is banned.");
    return;
  }

  session_ctx_t *existing = chat_room_find_user(&ctx->owner->room, new_name);
  if (existing != NULL && existing != ctx) {
    session_send_system_line(ctx, "That name is already taken.");
    return;
  }

  char old_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(old_name, sizeof(old_name), "%s", ctx->user.name);
  snprintf(ctx->user.name, sizeof(ctx->user.name), "%s", new_name);

  char announcement[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(announcement, sizeof(announcement), "* %s is now known as %s", old_name, ctx->user.name);
  host_history_record_system(ctx->owner, announcement);
  chat_room_broadcast(&ctx->owner->room, announcement, NULL);
  session_apply_saved_preferences(ctx);
  session_send_system_line(ctx, "Display name updated.");
}

static void session_handle_exit(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->should_exit = true;
  session_send_system_line(ctx, "Disconnecting... bye!");
  if (ctx->channel != NULL) {
    ssh_channel_send_eof(ctx->channel);
  }
}

static void session_handle_pardon(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to pardon users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /pardon <user|ip>");
    return;
  }

  char token[SSH_CHATTER_IP_LEN];
  snprintf(token, sizeof(token), "%s", arguments);
  trim_whitespace_inplace(token);

  if (token[0] == '\0') {
    session_send_system_line(ctx, "Usage: /pardon <user|ip>");
    return;
  }

  if (host_remove_ban_entry(ctx->owner, token)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Ban lifted for '%s'.", token);
    session_send_system_line(ctx, message);
  } else {
    session_send_system_line(ctx, "No matching ban found.");
  }
}

static session_ctx_t *chat_room_find_user(chat_room_t *room, const char *username) {
  if (room == NULL || username == NULL) {
    return NULL;
  }

  session_ctx_t *result = NULL;
  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    session_ctx_t *member = room->members[idx];
    if (member == NULL) {
      continue;
    }

    if (strncmp(member->user.name, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      result = member;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);

  return result;
}

static bool host_is_ip_banned(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  bool banned = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].ip, ip, SSH_CHATTER_IP_LEN) == 0) {
      banned = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return banned;
}

static bool host_is_username_banned(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return false;
  }

  bool banned = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].username, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      banned = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return banned;
}

static bool host_add_ban_entry(host_t *host, const char *username, const char *ip) {
  if (host == NULL) {
    return false;
  }

  bool added = false;
  pthread_mutex_lock(&host->lock);
  if (host->ban_count >= SSH_CHATTER_MAX_BANS) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }

  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    const bool username_match = (username != NULL && username[0] != '\0' &&
                                 strncmp(host->bans[idx].username, username, SSH_CHATTER_USERNAME_LEN) == 0);
    const bool ip_match = (ip != NULL && ip[0] != '\0' &&
                           strncmp(host->bans[idx].ip, ip, SSH_CHATTER_IP_LEN) == 0);
    if (username_match || ip_match) {
      pthread_mutex_unlock(&host->lock);
      return true;
    }
  }

  strncpy(host->bans[host->ban_count].username,
          username != NULL ? username : "", SSH_CHATTER_USERNAME_LEN - 1U);
  host->bans[host->ban_count].username[SSH_CHATTER_USERNAME_LEN - 1U] = '\0';
  strncpy(host->bans[host->ban_count].ip, ip != NULL ? ip : "", SSH_CHATTER_IP_LEN - 1U);
  host->bans[host->ban_count].ip[SSH_CHATTER_IP_LEN - 1U] = '\0';
  ++host->ban_count;
  added = true;

  pthread_mutex_unlock(&host->lock);
  return added;
}

static bool host_remove_ban_entry(host_t *host, const char *token) {
  if (host == NULL || token == NULL || token[0] == '\0') {
    return false;
  }

  bool removed = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].username, token, SSH_CHATTER_USERNAME_LEN) == 0 ||
        strncmp(host->bans[idx].ip, token, SSH_CHATTER_IP_LEN) == 0) {
      for (size_t shift = idx; shift + 1U < host->ban_count; ++shift) {
        host->bans[shift] = host->bans[shift + 1U];
      }
      memset(&host->bans[host->ban_count - 1U], 0, sizeof(host->bans[host->ban_count - 1U]));
      --host->ban_count;
      removed = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return removed;
}

static bool session_parse_command(const char *line, const char *command, const char **arguments) {
  size_t command_len = strlen(command);

  if (strncmp(line, command, command_len) == 0) {
    const char *args = line + command_len;

    while (*args == ' ' || *args == '\t') {
      ++args;
    }

    *arguments = args;
    return true;
  }
  return false;
}

static void session_dispatch_command(session_ctx_t *ctx, const char *line) {
  const char *arguments = NULL;

  if (strncmp(line, "/help", 5) == 0) {
    session_print_help(ctx);
    return;
  }

  if (strncmp(line, "/exit", 5) == 0) {
    session_handle_exit(ctx);
    return;
  }

  if (session_parse_command(line, "/nick", &arguments)) {
    session_handle_nick(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/pm", &arguments)) {
    session_handle_pm(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/motd", &arguments)) {
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /motd");
    } else {
      session_handle_motd(ctx);
    }
    return;
  }

  if (session_parse_command(line, "/users", &arguments)) {
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /users");
    } else {
      session_handle_usercount(ctx);
    }
    return;
  }

  if (session_parse_command(line, "/search", &arguments)) {
    session_handle_search(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/image", &arguments)) {
    session_handle_image(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/video", &arguments)) {
    session_handle_video(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/audio", &arguments)) {
    session_handle_audio(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/files", &arguments)) {
    session_handle_files(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/ban", &arguments)) {
    session_handle_ban(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/pardon", &arguments)) {
    session_handle_pardon(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/poke", &arguments)) {
    session_handle_poke(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/color", &arguments)) {
    session_handle_color(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/systemcolor", &arguments)) {
    session_handle_system_color(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/palette", &arguments)) {
    session_handle_palette(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/image-to-ascii", &arguments)) {
    session_handle_image_to_ascii(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/today", &arguments)) {
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /today");
    } else {
      session_handle_today(ctx);
    }
    return;
  }

  if (session_parse_command(line, "/date", &arguments)) {
    session_handle_date(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/os", &arguments)) {
    session_handle_os(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/getos", &arguments)) {
    session_handle_getos(ctx, arguments);
    return;
  }

  if (session_parse_command(line, "/pair", &arguments)) {
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /pair");
    } else {
      session_handle_pair(ctx);
    }
    return;
  }

  if (session_parse_command(line, "/connected", &arguments)) {
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /connected");
    } else {
      session_handle_connected(ctx);
    }
    return;
  }

  if (session_parse_command(line, "/poll", &arguments)) {
    session_handle_poll(ctx, arguments);
    return;
  }

  if (line[0] == '/') {
    if (isdigit((unsigned char)line[1])) {
      char *endptr = NULL;
      unsigned long vote_index = strtoul(line + 1, &endptr, 10);
      const unsigned long max_vote = sizeof(ctx->owner->poll.options) / sizeof(ctx->owner->poll.options[0]);
      if (vote_index >= 1UL && vote_index <= max_vote) {
        while (endptr != NULL && (*endptr == ' ' || *endptr == '\t')) {
          ++endptr;
        }
        if (endptr == NULL || *endptr == '\0') {
          session_handle_vote(ctx, (size_t)(vote_index - 1UL));
          return;
        }
      }
    }
    for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
      const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
      size_t command_len = strlen(descriptor->command);
      if (strncmp(line + 1, descriptor->command, command_len) != 0) {
        continue;
      }
      const char trailing = line[1 + command_len];
      if (!(trailing == '\0' || isspace((unsigned char)trailing))) {
        continue;
      }

      const char *arguments = line + 1 + command_len;
      while (*arguments == ' ' || *arguments == '\t') {
        ++arguments;
      }
      session_handle_reaction(ctx, idx, arguments);
      return;
    }
  }

  session_send_system_line(ctx, "Unknown command. Type /help for help.");
}

static void trim_whitespace_inplace(char *text) {
  if (text == NULL) {
    return;
  }

  char *start = text;
  while (*start != '\0' && isspace((unsigned char)*start)) {
    ++start;
  }

  char *end = text + strlen(text);
  while (end > start && isspace((unsigned char)*(end - 1))) {
    --end;
  }

  const size_t length = (size_t)(end - start);
  if (start != text && length > 0U) {
    memmove(text, start, length);
  }
  text[length] = '\0';
}

static void session_normalize_newlines(char *text) {
  if (text == NULL) {
    return;
  }

  size_t read_idx = 0U;
  size_t write_idx = 0U;
  while (text[read_idx] != '\0') {
    char ch = text[read_idx++];
    if (ch == '\r') {
      if (text[read_idx] == '\n') {
        ++read_idx;
      }
      text[write_idx++] = '\n';
    } else {
      text[write_idx++] = ch;
    }
  }

  text[write_idx] = '\0';
}

static bool timezone_sanitize_identifier(const char *input, char *output, size_t length) {
  if (input == NULL || output == NULL || length == 0U) {
    return false;
  }

  size_t out_idx = 0U;
  bool last_was_slash = true;

  for (size_t idx = 0U; input[idx] != '\0'; ++idx) {
    unsigned char ch = (unsigned char)input[idx];
    if (isspace(ch)) {
      return false;
    }

    if (ch == '/') {
      if (last_was_slash) {
        return false;
      }
      if (out_idx + 1U >= length) {
        return false;
      }
      output[out_idx++] = '/';
      last_was_slash = true;
      continue;
    }

    if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '+' || ch == '.')) {
      return false;
    }

    if (out_idx + 1U >= length) {
      return false;
    }
    output[out_idx++] = (char)ch;
    last_was_slash = false;
  }

  if (out_idx == 0U || last_was_slash) {
    return false;
  }

  output[out_idx] = '\0';

  if (output[0] == '/' || strstr(output, "..") != NULL) {
    return false;
  }

  return true;
}

static bool timezone_resolve_identifier(const char *input, char *resolved, size_t length) {
  if (input == NULL || input[0] == '\0' || resolved == NULL || length == 0U) {
    return false;
  }

  static const char kTimezoneDir[] = "/usr/share/zoneinfo";

  char full_path[PATH_MAX];
  int full_written = snprintf(full_path, sizeof(full_path), "%s/%s", kTimezoneDir, input);
  if (full_written >= 0 && (size_t)full_written < sizeof(full_path) && access(full_path, R_OK) == 0) {
    int copy_written = snprintf(resolved, length, "%s", input);
    return copy_written >= 0 && (size_t)copy_written < length;
  }

  char working[PATH_MAX];
  int working_written = snprintf(working, sizeof(working), "%s", input);
  if (working_written < 0 || (size_t)working_written >= sizeof(working)) {
    return false;
  }

  char accumulated[PATH_MAX];
  accumulated[0] = '\0';
  size_t accumulated_len = 0U;
  char current_dir[PATH_MAX];
  int dir_written = snprintf(current_dir, sizeof(current_dir), "%s", kTimezoneDir);
  if (dir_written < 0 || (size_t)dir_written >= sizeof(current_dir)) {
    return false;
  }

  char *saveptr = NULL;
  char *segment = strtok_r(working, "/", &saveptr);
  if (segment == NULL) {
    return false;
  }

  while (segment != NULL) {
    DIR *dir = opendir(current_dir);
    if (dir == NULL) {
      return false;
    }

    bool found = false;
    char matched[NAME_MAX + 1];
    matched[0] = '\0';
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_name[0] == '.') {
        if (entry->d_name[1] == '\0') {
          continue;
        }
        if (entry->d_name[1] == '.' && entry->d_name[2] == '\0') {
          continue;
        }
      }

      if (strcasecmp(entry->d_name, segment) == 0) {
        found = true;
        snprintf(matched, sizeof(matched), "%s", entry->d_name);
        break;
      }
    }
    closedir(dir);

    if (!found) {
      return false;
    }

    if (accumulated_len > 0U) {
      if (accumulated_len + 1U >= sizeof(accumulated)) {
        return false;
      }
      accumulated[accumulated_len++] = '/';
    }

    size_t match_len = strlen(matched);
    if (accumulated_len + match_len >= sizeof(accumulated)) {
      return false;
    }
    memcpy(accumulated + accumulated_len, matched, match_len);
    accumulated_len += match_len;
    accumulated[accumulated_len] = '\0';

    dir_written = snprintf(current_dir, sizeof(current_dir), "%s/%s", kTimezoneDir, accumulated);
    if (dir_written < 0 || (size_t)dir_written >= sizeof(current_dir)) {
      return false;
    }

    segment = strtok_r(NULL, "/", &saveptr);
  }

  if (accumulated_len == 0U) {
    return false;
  }

  full_written = snprintf(full_path, sizeof(full_path), "%s/%s", kTimezoneDir, accumulated);
  if (full_written < 0 || (size_t)full_written >= sizeof(full_path)) {
    return false;
  }

  if (access(full_path, R_OK) != 0) {
    return false;
  }

  int copy_written = snprintf(resolved, length, "%s", accumulated);
  return copy_written >= 0 && (size_t)copy_written < length;
}

static const os_descriptor_t *session_lookup_os_descriptor(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < sizeof(OS_CATALOG) / sizeof(OS_CATALOG[0]); ++idx) {
    if (strcasecmp(OS_CATALOG[idx].name, name) == 0) {
      return &OS_CATALOG[idx];
    }
  }

  return NULL;
}

static const char *lookup_color_code(const color_entry_t *entries, size_t entry_count, const char *name) {
  if (entries == NULL || name == NULL) {
    return NULL;
  }

  for (size_t idx = 0; idx < entry_count; ++idx) {
    if (strcasecmp(entries[idx].name, name) == 0) {
      return entries[idx].code;
    }
  }

  return NULL;
}

static const palette_descriptor_t *palette_find_descriptor(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < sizeof(PALETTE_DEFINITIONS) / sizeof(PALETTE_DEFINITIONS[0]); ++idx) {
    if (strcasecmp(PALETTE_DEFINITIONS[idx].name, name) == 0) {
      return &PALETTE_DEFINITIONS[idx];
    }
  }

  return NULL;
}

static bool palette_apply_to_session(session_ctx_t *ctx, const palette_descriptor_t *descriptor) {
  if (ctx == NULL || descriptor == NULL) {
    return false;
  }

  const char *user_color_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->user_color_name);
  const char *user_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->user_highlight_name);
  const char *system_fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->system_fg_name);
  const char *system_bg_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_bg_name);
  const char *system_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_highlight_name);

  if (user_color_code == NULL || user_highlight_code == NULL || system_fg_code == NULL || system_bg_code == NULL ||
      system_highlight_code == NULL) {
    return false;
  }

  ctx->user_color_code = user_color_code;
  ctx->user_highlight_code = user_highlight_code;
  ctx->user_is_bold = descriptor->user_is_bold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", descriptor->user_color_name);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", descriptor->user_highlight_name);

  ctx->system_fg_code = system_fg_code;
  ctx->system_bg_code = system_bg_code;
  ctx->system_highlight_code = system_highlight_code;
  ctx->system_is_bold = descriptor->system_is_bold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", descriptor->system_fg_name);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", descriptor->system_bg_name);
  snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", descriptor->system_highlight_name);

  return true;
}

static void host_apply_palette_descriptor(host_t *host, const palette_descriptor_t *descriptor) {
  if (host == NULL || descriptor == NULL) {
    return;
  }

  const char *user_color_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->user_color_name);
  const char *user_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->user_highlight_name);
  const char *system_fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->system_fg_name);
  const char *system_bg_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_bg_name);
  const char *system_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_highlight_name);

  if (user_color_code == NULL) {
    user_color_code = ANSI_GREEN;
  }
  if (user_highlight_code == NULL) {
    user_highlight_code = ANSI_BG_DEFAULT;
  }
  if (system_fg_code == NULL) {
    system_fg_code = ANSI_WHITE;
  }
  if (system_bg_code == NULL) {
    system_bg_code = ANSI_BG_BLUE;
  }
  if (system_highlight_code == NULL) {
    system_highlight_code = ANSI_BG_YELLOW;
  }

  host->user_theme.userColor = user_color_code;
  host->user_theme.highlight = user_highlight_code;
  host->user_theme.isBold = descriptor->user_is_bold;
  host->system_theme.foregroundColor = system_fg_code;
  host->system_theme.backgroundColor = system_bg_code;
  host->system_theme.highlightColor = system_highlight_code;
  host->system_theme.isBold = descriptor->system_is_bold;

  snprintf(host->default_user_color_name, sizeof(host->default_user_color_name), "%s", descriptor->user_color_name);
  snprintf(host->default_user_highlight_name, sizeof(host->default_user_highlight_name), "%s",
           descriptor->user_highlight_name);
  snprintf(host->default_system_fg_name, sizeof(host->default_system_fg_name), "%s", descriptor->system_fg_name);
  snprintf(host->default_system_bg_name, sizeof(host->default_system_bg_name), "%s", descriptor->system_bg_name);
  snprintf(host->default_system_highlight_name, sizeof(host->default_system_highlight_name), "%s",
           descriptor->system_highlight_name);
}

static bool parse_bool_token(const char *token, bool *value) {
  if (token == NULL || value == NULL) {
    return false;
  }

  if (strcasecmp(token, "true") == 0 || strcasecmp(token, "yes") == 0 || strcasecmp(token, "on") == 0 ||
      strcasecmp(token, "bold") == 0) {
    *value = true;
    return true;
  }

  if (strcasecmp(token, "false") == 0 || strcasecmp(token, "no") == 0 || strcasecmp(token, "off") == 0 ||
      strcasecmp(token, "normal") == 0) {
    *value = false;
    return true;
  }

  return false;
}

static void session_cleanup(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->channel != NULL) {
    ssh_channel_send_eof(ctx->channel);
    ssh_channel_close(ctx->channel);
    ssh_channel_free(ctx->channel);
    ctx->channel = NULL;
  }

  if (ctx->session != NULL) {
    ssh_disconnect(ctx->session);
    ssh_free(ctx->session);
    ctx->session = NULL;
  }

  free(ctx);
}

static void *session_thread(void *arg) {
  session_ctx_t *ctx = (session_ctx_t *)arg;
  if (ctx == NULL) {
    return NULL;
  }

  session_apply_theme_defaults(ctx);

  if (session_authenticate(ctx) != 0) {
    humanized_log_error("session", "authentication failed", EACCES);
    session_cleanup(ctx);
    return NULL;
  }

  if (session_accept_channel(ctx) != 0) {
    humanized_log_error("session", "failed to open channel", EIO);
    session_cleanup(ctx);
    return NULL;
  }

  if (session_prepare_shell(ctx) != 0) {
    humanized_log_error("session", "shell negotiation failed", EPROTO);
    session_cleanup(ctx);
    return NULL;
  }

  session_assign_lan_privileges(ctx);
  session_apply_saved_preferences(ctx);

  if (host_is_ip_banned(ctx->owner, ctx->client_ip) || host_is_username_banned(ctx->owner, ctx->user.name)) {
    session_send_system_line(ctx, "You are banned from this server.");
    session_cleanup(ctx);
    return NULL;
  }

  session_ctx_t *existing = chat_room_find_user(&ctx->owner->room, ctx->user.name);
  if (existing != NULL) {
    ctx->username_conflict = true;
    printf("[reject] username in use: %s\n", ctx->user.name);
    session_render_banner(ctx);
    char in_use[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(in_use, sizeof(in_use), "The username '%s' is already in use.", ctx->user.name);
    session_send_system_line(ctx, in_use);
    session_send_system_line(ctx,
                             "Reconnect with a different username by running: ssh newname@<server> (or ssh -l newname <server>).");
    session_send_system_line(ctx, "Type /exit to quit.");
  } else {
    chat_room_add(&ctx->owner->room, ctx);
    ctx->has_joined_room = true;
    printf("[join] %s\n", ctx->user.name);

    session_render_banner(ctx);
    session_send_history(ctx);
    if (ctx->owner->motd[0] != '\0') {
      session_send_system_line(ctx, ctx->owner->motd);
    }
    session_send_system_line(ctx, "Type /help to explore available commands.");

    char join_message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(join_message, sizeof(join_message), "* %s has joined the chat", ctx->user.name);
    host_history_record_system(ctx->owner, join_message);
    chat_room_broadcast(&ctx->owner->room, join_message, NULL);
  }

  session_clear_input(ctx);
  session_render_prompt(ctx, true);

  char buffer[SSH_CHATTER_MAX_INPUT_LEN];
  while (!ctx->should_exit) {
    const int bytes_read = ssh_channel_read(ctx->channel, buffer, sizeof(buffer) - 1U, 0);
    if (bytes_read <= 0) {
      break;
    }

    for (int idx = 0; idx < bytes_read; ++idx) {
      const char ch = buffer[idx];

      if (session_consume_escape_sequence(ctx, ch)) {
        continue;
      }

      if (ch == '\r' || ch == '\n') {
        session_local_echo_char(ctx, '\n');
        if (ctx->input_length > 0U) {
          ctx->input_buffer[ctx->input_length] = '\0';
          session_history_record(ctx, ctx->input_buffer);
          session_process_line(ctx, ctx->input_buffer);
        }
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
        continue;
      }

      if (ch == '\b' || ch == 0x7f) {
        ctx->input_history_position = -1;
        ctx->history_scroll_position = 0U;
        session_local_backspace(ctx);
        continue;
      }

      if (ch == '\t') {
        if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
          ctx->input_history_position = -1;
          ctx->history_scroll_position = 0U;
          ctx->input_buffer[ctx->input_length++] = ' ';
          session_local_echo_char(ctx, ' ');
        }
        continue;
      }

      if ((unsigned char)ch < 0x20U) {
        continue;
      }

      if (ctx->input_length + 1U >= sizeof(ctx->input_buffer)) {
        ctx->input_buffer[sizeof(ctx->input_buffer) - 1U] = '\0';
        session_history_record(ctx, ctx->input_buffer);
        session_process_line(ctx, ctx->input_buffer);
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
      }

      if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
        ctx->input_history_position = -1;
        ctx->history_scroll_position = 0U;
        ctx->input_buffer[ctx->input_length++] = ch;
        session_local_echo_char(ctx, ch);
      }
    }

    if (ctx->should_exit) {
      break;
    }
  }

  if (!ctx->should_exit && ctx->input_length > 0U) {
    ctx->input_buffer[ctx->input_length] = '\0';
    session_history_record(ctx, ctx->input_buffer);
    session_process_line(ctx, ctx->input_buffer);
    session_clear_input(ctx);
  }

  if (ctx->has_joined_room) {
    printf("[part] %s\n", ctx->user.name);
    char part_message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(part_message, sizeof(part_message), "* %s has left the chat", ctx->user.name);
    host_history_record_system(ctx->owner, part_message);
    chat_room_broadcast(&ctx->owner->room, part_message, NULL);
    chat_room_remove(&ctx->owner->room, ctx);
  }
  session_cleanup(ctx);

  return NULL;
}

void host_init(host_t *host, auth_profile_t *auth) {
  if (host == NULL) {
    return;
  }

  chat_room_init(&host->room);
  host->listener.handle = NULL;
  host->auth = auth;
  const palette_descriptor_t *default_palette = palette_find_descriptor("clean");
  if (default_palette != NULL) {
    host_apply_palette_descriptor(host, default_palette);
  } else {
    host->user_theme.userColor = ANSI_GREEN;
    host->user_theme.highlight = ANSI_BG_DEFAULT;
    host->user_theme.isBold = false;
    host->system_theme.backgroundColor = ANSI_BG_BLUE;
    host->system_theme.foregroundColor = ANSI_WHITE;
    host->system_theme.highlightColor = ANSI_BG_YELLOW;
    host->system_theme.isBold = true;
    snprintf(host->default_user_color_name, sizeof(host->default_user_color_name), "%s", "green");
    snprintf(host->default_user_highlight_name, sizeof(host->default_user_highlight_name), "%s", "default");
    snprintf(host->default_system_fg_name, sizeof(host->default_system_fg_name), "%s", "white");
    snprintf(host->default_system_bg_name, sizeof(host->default_system_bg_name), "%s", "blue");
    snprintf(host->default_system_highlight_name, sizeof(host->default_system_highlight_name), "%s", "yellow");
  }
  host->ban_count = 0U;
  memset(host->bans, 0, sizeof(host->bans));
  snprintf(host->version, sizeof(host->version), "ssh-chatter (C, rolling release)");
  snprintf(host->motd, sizeof(host->motd),
  "Welcome to ssh-chat!\n"
  "\033[1G- Be polite to each other\n"
  "\033[1G- fun fact: this server is written in pure c.\n"
  "\033[1G============================================\n"
  "\033[1G _      ____  ____  _____ ____  _        ____  _ \n"
  "\033[1G/ \\__/|/  _ \\/  _ \\/  __//  __\\/ \\  /|  /   _\\/ \\\n"
  "\033[1G| |\\/||| / \\|| | \\||  \\  |  \\/|| |\\ ||  |  /  | |\n"
  "\033[1G| |  ||| \\_/|| |_/||  /_ |    /| | \\||  |  \\__\\_/\n"
  "\033[1G\\_/  \\|\\____/\\____/\\____\\\\_/\\_\\\\_/  \\|  \\____/(_)\n"
  "\033[1G                                                 \n"
  "\033[1G============================================\n");


  host->connection_count = 0U;
  host->history_start = 0U;
  host->history_count = 0U;
  memset(host->history, 0, sizeof(host->history));
  host->next_message_id = 1U;
  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;
  host->state_file_path[0] = '\0';
  host_state_resolve_path(host);
  pthread_mutex_init(&host->lock, NULL);
  host->poll.active = false;
  host->poll.id = 0U;
  host->poll.option_count = 0U;
  memset(host->poll.question, 0, sizeof(host->poll.question));
  for (size_t idx = 0U; idx < sizeof(host->poll.options) / sizeof(host->poll.options[0]); ++idx) {
    host->poll.options[idx].text[0] = '\0';
    host->poll.options[idx].votes = 0U;
  }
  host->random_seeded = false;

  (void)host_try_load_motd_from_path(host, "/etc/chatter/motd");

  (void)host_try_load_motd_from_path(host, "/etc/ssh-chatter/motd");

  host_state_load(host);
}

static bool host_try_load_motd_from_path(host_t *host, const char *path) {
  if (host == NULL || path == NULL || path[0] == '\0') {
    return false;
  }

  FILE *motd_file = fopen(path, "r");
  if (motd_file == NULL) {
    return false;
  }

  char motd_buffer[sizeof(host->motd)];
  size_t total_read = 0U;
  // TODO: Extract a shared helper (e.g. host_read_text_file) so these buffered
  // reads share the same error handling path as other file loaders.
  while (total_read < sizeof(motd_buffer) - 1U) {
    const size_t bytes_to_read = sizeof(motd_buffer) - 1U - total_read;
    const size_t chunk = fread(motd_buffer + total_read, 1U, bytes_to_read, motd_file);
    if (chunk == 0U) {
      if (ferror(motd_file)) {
        const int read_error = errno;
        const int close_result = fclose(motd_file);
        if (close_result != 0) {
          const int close_error = errno;
          humanized_log_error("host", "failed to close motd file", close_error);
        }
        humanized_log_error("host", "failed to read motd file", read_error);
        return false;
      }
      break;
    }
    total_read += chunk;
    if (feof(motd_file)) {
      break;
    }
  }

  motd_buffer[total_read] = '\0';

  if (fclose(motd_file) != 0) {
    const int close_error = errno;
    humanized_log_error("host", "failed to close motd file", close_error);
  }

  pthread_mutex_lock(&host->lock);
  snprintf(host->motd, sizeof(host->motd), "%s", motd_buffer);
  pthread_mutex_unlock(&host->lock);
  return true;
}

void host_set_motd(host_t *host, const char *motd) {
  if (host == NULL || motd == NULL) {
    return;
  }

  if (host_try_load_motd_from_path(host, motd)) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  snprintf(host->motd, sizeof(host->motd), "%s", normalized);
  pthread_mutex_unlock(&host->lock);
}

int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory) {
  if (host == NULL) {
    return -1;
  }

  const char *address = bind_addr != NULL ? bind_addr : "0.0.0.0";
  const char *bind_port = port != NULL ? port : "2222";
  const char *rsa_filename = "ssh_host_rsa_key";
  const char *rsa_key_path = NULL;
  char resolved_rsa_key[PATH_MAX];

  if (key_directory != NULL && key_directory[0] != '\0') {
    const size_t dir_len = strlen(key_directory);
    if (dir_len >= sizeof(resolved_rsa_key)) {
      humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
      return -1;
    }
    const bool needs_separator = dir_len > 0 && key_directory[dir_len - 1U] != '/';
    int written = snprintf(resolved_rsa_key, sizeof(resolved_rsa_key), "%s%s%s", key_directory,
                           needs_separator ? "/" : "", rsa_filename);
    if (written < 0 || (size_t)written >= sizeof(resolved_rsa_key)) {
      humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
      return -1;
    }
    rsa_key_path = resolved_rsa_key;
  } else {
    const char *candidates[] = {rsa_filename, "/etc/ssh/ssh_host_rsa_key"};
    for (size_t idx = 0; idx < sizeof(candidates) / sizeof(candidates[0]); ++idx) {
      if (access(candidates[idx], R_OK) == 0) {
        rsa_key_path = candidates[idx];
        break;
      }
    }
  }

  if (rsa_key_path == NULL) {
    humanized_log_error("host", "unable to locate RSA host key", ENOENT);
    return -1;
  }

  if (access(rsa_key_path, R_OK) != 0) {
    humanized_log_error("host", "unable to access RSA host key", errno);
    return -1;
  }

  ssh_bind bind_handle = ssh_bind_new();
  if (bind_handle == NULL) {
    humanized_log_error("host", "failed to allocate ssh_bind", ENOMEM);
    return -1;
  }

  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
  errno = 0;
  bool key_loaded = false;
  if (ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_RSAKEY, rsa_key_path) == SSH_OK) {
    key_loaded = true;
  } else {
    const char *error_message = ssh_get_error(bind_handle);
    const bool unsupported_option = (error_message != NULL &&
                                     strstr(error_message, "Unknown ssh option") != NULL) ||
                                    errno == ENOTSUP;
    if (!unsupported_option) {
      humanized_log_error("host", error_message, errno != 0 ? errno : EIO);
      ssh_bind_free(bind_handle);
      return -1;
    }

    ssh_key imported_key = NULL;
    if (ssh_pki_import_privkey_file(rsa_key_path, NULL, NULL, NULL, &imported_key) != SSH_OK ||
        imported_key == NULL) {
      humanized_log_error("host", "failed to import RSA host key", EIO);
      ssh_bind_free(bind_handle);
      return -1;
    }

    const int import_result =
        ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_IMPORT_KEY, imported_key);
    ssh_key_free(imported_key);
    if (import_result != SSH_OK) {
      humanized_log_error("host", ssh_get_error(bind_handle), errno != 0 ? errno : EIO);
      ssh_bind_free(bind_handle);
      return -1;
    }

    key_loaded = true;
  }

  if (!key_loaded) {
    humanized_log_error("host", "failed to configure host key", EIO);
    ssh_bind_free(bind_handle);
    return -1;
  }

  if (ssh_bind_listen(bind_handle) < 0) {
    humanized_log_error("host", ssh_get_error(bind_handle), EIO);
    ssh_bind_free(bind_handle);
    return -1;
  }

  host->listener.handle = bind_handle;
  printf("[listener] listening on %s:%s\n", address, bind_port);

  while (true) {
    ssh_session session = ssh_new();
    if (session == NULL) {
      humanized_log_error("host", "failed to allocate session", ENOMEM);
      continue;
    }

    if (ssh_bind_accept(bind_handle, session) == SSH_ERROR) {
      humanized_log_error("host", ssh_get_error(bind_handle), EIO);
      ssh_free(session);
      continue;
    }

    if (ssh_handle_key_exchange(session) != SSH_OK) {
      humanized_log_error("host", ssh_get_error(session), EPROTO);
      ssh_disconnect(session);
      ssh_free(session);
      continue;
    }

    char peer_address[NI_MAXHOST];
    session_describe_peer(session, peer_address, sizeof(peer_address));
    if (peer_address[0] == '\0') {
      strncpy(peer_address, "unknown", sizeof(peer_address) - 1U);
      peer_address[sizeof(peer_address) - 1U] = '\0';
    }

    printf("[connect] accepted client from %s\n", peer_address);

    session_ctx_t *ctx = calloc(1U, sizeof(session_ctx_t));
    if (ctx == NULL) {
      humanized_log_error("host", "failed to allocate session context", ENOMEM);
      ssh_disconnect(session);
      ssh_free(session);
      continue;
    }

    ctx->session = session;
    ctx->channel = NULL;
    ctx->owner = host;
    ctx->auth = (auth_profile_t){0};
    snprintf(ctx->client_ip, sizeof(ctx->client_ip), "%.*s", (int)sizeof(ctx->client_ip) - 1, peer_address);

    pthread_mutex_lock(&host->lock);
    ++host->connection_count;
    snprintf(ctx->user.name, sizeof(ctx->user.name), "Guest%zu", host->connection_count);
    ctx->user.is_operator = false;
    ctx->user.is_lan_operator = false;
    pthread_mutex_unlock(&host->lock);

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, session_thread, ctx) != 0) {
      humanized_log_error("host", "failed to spawn session thread", errno);
      session_cleanup(ctx);
      continue;
    }

    pthread_detach(thread_id);
  }

  ssh_bind_free(bind_handle);
  host->listener.handle = NULL;
  return 0;
}
