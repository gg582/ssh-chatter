#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "host.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "humanized/humanized.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif

typedef struct {
  const char *name;
  const char *code;
} color_entry_t;

static const char *host_key_type_to_name(ssh_keytypes_e key_type);
static bool host_configure_legacy_host_key(ssh_bind handle, ssh_keytypes_e key_type,
                                          const char *path);
static bool host_option_is_unsupported(const char *error_message, int error_code,
                                       const char *key_path);
static void session_send_pre_handshake_notice(ssh_session session, const char *message);
static bool host_error_indicates_hostkey_mismatch(const char *error_message);

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

static const char *kDefaultMotdText =
    "Welcome to ssh-chat!\n"
    "\033[1G- Be polite to each other\n"
    "\033[1G- fun fact: this server is written in pure c.\n";

static const char *const kModernCAsciiArt[] = {
    "\033[1G============================================",
    "\033[1G _      ____  ____  _____ ____  _        ____  _ ",
    "\033[1G/ \\__/|/  _ \\/  _ \\/  __//  __\\/ \\  /|  /   _\\/ \\",
    "\033[1G| |\\/||| / \\|| | \\||  \\  |  \\/|| |\\ ||  |  /  | |",
    "\033[1G| |  ||| \\_/|| |_/||  /_ |    /| | \\||  |  \\__\\_/",
    "\033[1G\\_/  \\|\\____/\\____/\\____\\\\_/\\_\\\\_/  \\|  \\____/(_)",
    "\033[1G                                                 ",
    "\033[1G============================================",
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
static void session_send_system_line(session_ctx_t *ctx, const char *message);
static void session_send_multiline_system_text(session_ctx_t *ctx, const char *text);
static void session_send_modern_c_ascii_art(session_ctx_t *ctx);
static void session_render_motd(session_ctx_t *ctx, const char *motd);
static bool session_fetch_motd(session_ctx_t *ctx, char *motd, size_t motd_len);
static void session_render_banner(session_ctx_t *ctx);
static void session_render_separator(session_ctx_t *ctx, const char *label);
static void session_render_prompt(session_ctx_t *ctx, bool include_separator);
static void session_local_echo_char(session_ctx_t *ctx, char ch);
static void session_local_backspace(session_ctx_t *ctx);
static void session_clear_input(session_ctx_t *ctx);
static void session_send_user_message(session_ctx_t *target, const session_ctx_t *from, const char *message);
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
static void session_handle_pardon(session_ctx_t *ctx, const char *arguments);
static bool session_line_is_exit_command(const char *line);
static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line);
static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count);
static size_t session_utf8_prev_char_len(const char *buffer, size_t length);
static int session_utf8_char_width(const char *bytes, size_t length);
static void host_history_record_user(host_t *host, const session_ctx_t *from, const char *message);
static void host_history_record_system(host_t *host, const char *message);
static void session_send_history(session_ctx_t *ctx);
static void host_history_append(host_t *host, const chat_history_entry_t *entry);
static user_preference_t *host_find_preference_locked(host_t *host, const char *username);
static user_preference_t *host_ensure_preference_locked(host_t *host, const char *username);
static void host_store_user_theme(host_t *host, const session_ctx_t *ctx);
static void host_store_system_theme(host_t *host, const session_ctx_t *ctx);
static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry);
static void host_state_resolve_path(host_t *host);
static void host_state_load(host_t *host);
static void host_state_save_locked(host_t *host);
static bool host_try_load_motd_from_path(host_t *host, const char *path);
static bool string_contains_case_insensitive(const char *haystack, const char *needle);

static const uint32_t HOST_STATE_MAGIC = 0x53484354U; /* 'SHCT' */
static const uint32_t HOST_STATE_VERSION = 1U;

typedef struct host_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t history_count;
  uint32_t preference_count;
} host_state_header_t;

typedef struct host_state_history_entry {
  uint8_t is_user_message;
  uint8_t user_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char message[SSH_CHATTER_MESSAGE_LIMIT];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
} host_state_history_entry_t;

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
} host_state_preference_entry_t;

static const char *host_key_type_to_name(ssh_keytypes_e key_type) {
  switch (key_type) {
    case SSH_KEYTYPE_RSA:
#if defined(SSH_KEYTYPE_RSA1)
    case SSH_KEYTYPE_RSA1:
#endif
      return "ssh-rsa";
    case SSH_KEYTYPE_DSS:
      return "ssh-dss";
#if defined(SSH_KEYTYPE_ED25519)
    case SSH_KEYTYPE_ED25519:
      return "ssh-ed25519";
#endif
#if defined(SSH_KEYTYPE_SK_ED25519)
    case SSH_KEYTYPE_SK_ED25519:
      return "sk-ssh-ed25519@openssh.com";
#endif
#if defined(SSH_KEYTYPE_SK_ECDSA)
    case SSH_KEYTYPE_SK_ECDSA:
      return "sk-ecdsa-sha2-nistp256@openssh.com";
#endif
#if defined(SSH_KEYTYPE_ECDSA)
    case SSH_KEYTYPE_ECDSA:
      return "ecdsa-sha2-nistp256";
#endif
#if defined(SSH_KEYTYPE_ECDSA_P256)
    case SSH_KEYTYPE_ECDSA_P256:
      return "ecdsa-sha2-nistp256";
#endif
#if defined(SSH_KEYTYPE_ECDSA_P384)
    case SSH_KEYTYPE_ECDSA_P384:
      return "ecdsa-sha2-nistp384";
#endif
#if defined(SSH_KEYTYPE_ECDSA_P521)
    case SSH_KEYTYPE_ECDSA_P521:
      return "ecdsa-sha2-nistp521";
#endif
    default:
      break;
  }
  return NULL;
}

static bool host_configure_legacy_host_key(ssh_bind handle, ssh_keytypes_e key_type,
                                          const char *path) {
  if (handle == NULL || path == NULL) {
    return false;
  }

  switch (key_type) {
    case SSH_KEYTYPE_RSA:
#if defined(SSH_BIND_OPTIONS_RSAKEY)
      return ssh_bind_options_set(handle, SSH_BIND_OPTIONS_RSAKEY, path) == SSH_OK;
#else
      return false;
#endif
    case SSH_KEYTYPE_DSS:
#if defined(SSH_BIND_OPTIONS_DSAKEY)
      return ssh_bind_options_set(handle, SSH_BIND_OPTIONS_DSAKEY, path) == SSH_OK;
#else
      return false;
#endif
#if defined(SSH_KEYTYPE_ED25519)
    case SSH_KEYTYPE_ED25519:
#if defined(SSH_BIND_OPTIONS_ED25519KEY)
      return ssh_bind_options_set(handle, SSH_BIND_OPTIONS_ED25519KEY, path) == SSH_OK;
#else
      return false;
#endif
#endif
#if defined(SSH_KEYTYPE_ECDSA)
    case SSH_KEYTYPE_ECDSA:
#endif
#if defined(SSH_KEYTYPE_ECDSA_P256)
    case SSH_KEYTYPE_ECDSA_P256:
#endif
#if defined(SSH_KEYTYPE_ECDSA_P384)
    case SSH_KEYTYPE_ECDSA_P384:
#endif
#if defined(SSH_KEYTYPE_ECDSA_P521)
    case SSH_KEYTYPE_ECDSA_P521:
#endif
#if defined(SSH_BIND_OPTIONS_ECDSAKEY)
      return ssh_bind_options_set(handle, SSH_BIND_OPTIONS_ECDSAKEY, path) == SSH_OK;
#else
      return false;
#endif
    default:
      break;
  }

  return false;
}

static bool host_option_is_unsupported(const char *error_message, int error_code,
                                       const char *key_path) {
  if (error_code == ENOTSUP) {
    return true;
  }

  if (error_message != NULL) {
    if (strstr(error_message, "Unknown ssh option") != NULL ||
        strstr(error_message, "Function not supported") != NULL ||
        strstr(error_message, "unsupported option") != NULL) {
      return true;
    }

    if (error_message[0] == '\0' && error_code == ENOENT && key_path != NULL &&
        access(key_path, R_OK) == 0) {
      return true;
    }
  }

  return false;
}

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
      session_send_user_message(member, from, message);
    } else {
      session_send_system_line(member, message);
    }
  }

  if (from != NULL) {
    printf("[broadcast:%s] %s\n", from->user.name, message);
  } else {
    printf("[broadcast] %s\n", message);
  }
}

static void host_history_append(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);

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

  pthread_mutex_unlock(&host->lock);
}

static void host_history_record_user(host_t *host, const session_ctx_t *from, const char *message) {
  if (host == NULL || from == NULL || message == NULL || message[0] == '\0') {
    return;
  }

  chat_history_entry_t entry = {0};
  entry.is_user_message = true;
  snprintf(entry.username, sizeof(entry.username), "%s", from->user.name);
  snprintf(entry.message, sizeof(entry.message), "%s", message);
  entry.user_color_code = from->user_color_code;
  entry.user_highlight_code = from->user_highlight_code;
  entry.user_is_bold = from->user_is_bold;
  snprintf(entry.user_color_name, sizeof(entry.user_color_name), "%s", from->user_color_name);
  snprintf(entry.user_highlight_name, sizeof(entry.user_highlight_name), "%s", from->user_highlight_name);

  host_history_normalize_entry(host, &entry);

  host_history_append(host, &entry);
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

  host_history_append(host, &entry);
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
  header.magic = HOST_STATE_MAGIC;
  header.version = HOST_STATE_VERSION;
  header.history_count = (uint32_t)host->history_count;
  header.preference_count = (uint32_t)preference_count;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  for (size_t idx = 0; success && idx < host->history_count; ++idx) {
    size_t history_index = (host->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    const chat_history_entry_t *entry = &host->history[history_index];

    host_state_history_entry_t serialized = {0};
    serialized.is_user_message = entry->is_user_message ? 1U : 0U;
    serialized.user_is_bold = entry->user_is_bold ? 1U : 0U;
    snprintf(serialized.username, sizeof(serialized.username), "%s", entry->username);
    snprintf(serialized.message, sizeof(serialized.message), "%s", entry->message);
    snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", entry->user_color_name);
    snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s",
             entry->user_highlight_name);

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

  host_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != HOST_STATE_MAGIC || header.version != HOST_STATE_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t history_count = header.history_count;
  if (history_count > SSH_CHATTER_HISTORY_LIMIT) {
    history_count = SSH_CHATTER_HISTORY_LIMIT;
  }

  pthread_mutex_lock(&host->lock);
  host->history_start = 0U;
  host->history_count = 0U;
  memset(host->history, 0, sizeof(host->history));

  for (uint32_t idx = 0; idx < history_count; ++idx) {
    host_state_history_entry_t serialized = {0};
    if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      break;
    }

    chat_history_entry_t *entry = &host->history[idx % SSH_CHATTER_HISTORY_LIMIT];
    memset(entry, 0, sizeof(*entry));
    entry->is_user_message = serialized.is_user_message != 0U;
    entry->user_is_bold = serialized.user_is_bold != 0U;
    snprintf(entry->username, sizeof(entry->username), "%s", serialized.username);
    snprintf(entry->message, sizeof(entry->message), "%s", serialized.message);
    snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.user_color_name);
    snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s", serialized.user_highlight_name);
    host_history_normalize_entry(host, entry);
    ++host->history_count;
  }

  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;

  uint32_t preference_count = header.preference_count;
  if (preference_count > SSH_CHATTER_MAX_PREFERENCES) {
    preference_count = SSH_CHATTER_MAX_PREFERENCES;
  }

  for (uint32_t idx = 0; idx < preference_count; ++idx) {
    host_state_preference_entry_t serialized = {0};
    if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      break;
    }

    if (host->preference_count >= SSH_CHATTER_MAX_PREFERENCES) {
      break;
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
    snprintf(pref->system_highlight_name, sizeof(pref->system_highlight_name), "%s", serialized.system_highlight_name);
    ++host->preference_count;
  }

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

static void session_send_multiline_system_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || text == NULL || text[0] == '\0') {
    return;
  }

  const char *line_start = text;
  while (*line_start != '\0') {
    const char *line_end = strchr(line_start, '\n');
    size_t line_len = line_end != NULL ? (size_t)(line_end - line_start) : strlen(line_start);

    while (line_len > 0U && line_start[line_len - 1U] == '\r') {
      --line_len;
    }

    char line_buffer[SSH_CHATTER_MESSAGE_LIMIT];
    if (line_len >= sizeof(line_buffer)) {
      line_len = sizeof(line_buffer) - 1U;
    }

    memcpy(line_buffer, line_start, line_len);
    line_buffer[line_len] = '\0';

    session_send_system_line(ctx, line_buffer);

    if (line_end == NULL) {
      break;
    }
    line_start = line_end + 1;
  }
}

static void session_send_modern_c_ascii_art(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  for (size_t idx = 0; idx < sizeof(kModernCAsciiArt) / sizeof(kModernCAsciiArt[0]); ++idx) {
    session_send_system_line(ctx, kModernCAsciiArt[idx]);
  }
}

static void session_render_motd(session_ctx_t *ctx, const char *motd) {
  if (ctx == NULL) {
    return;
  }

  if (motd != NULL && motd[0] != '\0') {
    session_send_multiline_system_text(ctx, motd);
  }

  session_send_modern_c_ascii_art(ctx);
}

static bool session_fetch_motd(session_ctx_t *ctx, char *motd, size_t motd_len) {
  if (motd == NULL || motd_len == 0U) {
    return false;
  }

  motd[0] = '\0';

  if (ctx == NULL || ctx->owner == NULL) {
    return false;
  }

  pthread_mutex_lock(&ctx->owner->lock);
  snprintf(motd, motd_len, "%s", ctx->owner->motd);
  pthread_mutex_unlock(&ctx->owner->lock);

  return motd[0] != '\0';
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
  snprintf(label_buffer, sizeof(label_buffer), "--- %s ", label);
  size_t label_len = strlen(label_buffer);
  if (label_len > total_width) {
    label_len = total_width;
    label_buffer[total_width] = '\0';
  }
  size_t remaining = total_width > label_len ? total_width - label_len : 0U;
  memset(content, '-', remaining);
  content[remaining] = '\0';

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s%s%s%s", hl, fg, bold, label_buffer, content, ANSI_RESET);
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
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  char prompt[64];
  snprintf(prompt, sizeof(prompt), "%s%s> %s", fg, bold, ANSI_RESET);
  ssh_channel_write(ctx->channel, prompt, strlen(prompt));

  if (ctx->input_length > 0U) {
    ssh_channel_write(ctx->channel, ctx->input_buffer, ctx->input_length);
  }
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
}

static void session_send_user_message(session_ctx_t *target, const session_ctx_t *from, const char *message) {
  if (target == NULL || target->channel == NULL || from == NULL || message == NULL) {
    return;
  }

  const char *highlight = from->user_highlight_code != NULL ? from->user_highlight_code : "";
  const char *color = from->user_color_code != NULL ? from->user_color_code : "";
  const char *bold = from->user_is_bold ? ANSI_BOLD : "";

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color, from->user.name, ANSI_RESET, message);
  session_send_line(target->channel, line);
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
}

static void session_send_history(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL || ctx->channel == NULL) {
    return;
  }

  chat_history_entry_t snapshot[SSH_CHATTER_HISTORY_LIMIT];
  size_t count = 0U;

  pthread_mutex_lock(&ctx->owner->lock);
  count = ctx->owner->history_count;
  for (size_t idx = 0; idx < count; ++idx) {
    size_t history_index = (ctx->owner->history_start + idx) % SSH_CHATTER_HISTORY_LIMIT;
    snapshot[idx] = ctx->owner->history[history_index];
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  if (count == 0U) {
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Recent activity (last %zu message%s):", count, count == 1U ? "" : "s");
  session_render_separator(ctx, "Recent activity");
  session_send_system_line(ctx, header);

  for (size_t idx = 0; idx < count; ++idx) {
    const chat_history_entry_t *entry = &snapshot[idx];
    if (entry->is_user_message) {
      const char *highlight = entry->user_highlight_code != NULL ? entry->user_highlight_code : "";
      const char *color = entry->user_color_code != NULL ? entry->user_color_code : "";
      const char *bold = entry->user_is_bold ? ANSI_BOLD : "";

      char line[SSH_CHATTER_MESSAGE_LIMIT + 64];
      snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color, entry->username, ANSI_RESET,
               entry->message);
      session_send_line(ctx->channel, line);
    } else {
      session_send_system_line(ctx, entry->message);
    }
  }

  session_render_separator(ctx, "Chatroom");
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
  session_send_system_line(ctx, "/color (text;highlight[;bold]) - style your handle");
  session_send_system_line(ctx,
                           "/systemcolor (fg;background[;highlight][;bold]) - style the interface (third value may "
                           "be highlight or bold; use /systemcolor reset to restore defaults)");
  session_send_system_line(ctx, "/poke <username>      - send a bell to call a user");
  session_send_system_line(ctx, "/ban <username>       - ban a user (operator only)");
  session_send_system_line(ctx, "/pardon <user|ip>     - remove a ban (operator only)");
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

  printf("[%s] %s\n", ctx->user.name, line);

  if (ctx->username_conflict) {
    session_handle_username_conflict_input(ctx, line);
    return;
  }

  if (line[0] == '/') {
    session_dispatch_command(ctx, line);
    return;
  }

  session_send_user_message(ctx, ctx, line);
  host_history_record_user(ctx->owner, ctx, line);
  chat_room_broadcast(&ctx->owner->room, line, ctx);
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
  if (!session_fetch_motd(ctx, motd, sizeof(motd))) {
    session_send_system_line(ctx, "No message of the day is configured.");
    return;
  }

  session_render_motd(ctx, motd);
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

static void session_dispatch_command(session_ctx_t *ctx, const char *line) {
  if (strncmp(line, "/help", 5) == 0) {
    session_print_help(ctx);
    return;
  }
  if (strncmp(line, "/exit", 5) == 0) {
    session_handle_exit(ctx);
    return;
  }
  if (strncmp(line, "/nick", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_nick(ctx, arguments);
    return;
  }
  if (strncmp(line, "/pm", 3) == 0) {
    const char *arguments = line + 3;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_pm(ctx, arguments);
    return;
  }
  if (strncmp(line, "/motd", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /motd");
    } else {
      session_handle_motd(ctx);
    }
    return;
  }
  if (strncmp(line, "/ban", 4) == 0) {
    const char *arguments = line + 4;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_ban(ctx, arguments);
    return;
  }
  if (strncmp(line, "/pardon", 7) == 0) {
    const char *arguments = line + 7;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_pardon(ctx, arguments);
    return;
  }
  if (strncmp(line, "/poke", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_poke(ctx, arguments);
    return;
  }
  if (strncmp(line, "/color", 6) == 0) {
    const char *arguments = line + 6;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_color(ctx, arguments);
    return;
  }
  if (strncmp(line, "/systemcolor", 12) == 0) {
    const char *arguments = line + 12;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_system_color(ctx, arguments);
    return;
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
    char motd[sizeof(ctx->owner->motd)];
    if (session_fetch_motd(ctx, motd, sizeof(motd))) {
      session_render_motd(ctx, motd);
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

      if (ch == '\r' || ch == '\n') {
        session_local_echo_char(ctx, '\n');
        if (ctx->input_length > 0U) {
          ctx->input_buffer[ctx->input_length] = '\0';
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
        session_local_backspace(ctx);
        continue;
      }

      if (ch == '\t') {
        if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
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
        session_process_line(ctx, ctx->input_buffer);
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
      }

      if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
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
  host->user_theme.userColor = ANSI_GREEN;
  host->user_theme.highlight = ANSI_BG_DEFAULT;
  host->user_theme.isBold = false;
  host->system_theme.backgroundColor = ANSI_BLUE;
  host->system_theme.foregroundColor = ANSI_WHITE;
  host->system_theme.highlightColor = ANSI_YELLOW;
  host->system_theme.isBold = true;
  snprintf(host->default_user_color_name, sizeof(host->default_user_color_name), "%s", "green");
  snprintf(host->default_user_highlight_name, sizeof(host->default_user_highlight_name), "%s", "default");
  snprintf(host->default_system_fg_name, sizeof(host->default_system_fg_name), "%s", "white");
  snprintf(host->default_system_bg_name, sizeof(host->default_system_bg_name), "%s", "blue");
  snprintf(host->default_system_highlight_name, sizeof(host->default_system_highlight_name), "%s", "yellow");
  host->ban_count = 0U;
  memset(host->bans, 0, sizeof(host->bans));
  snprintf(host->version, sizeof(host->version), "ssh-chatter (C, rolling release)");
  snprintf(host->motd, sizeof(host->motd), "%s", kDefaultMotdText);


  host->connection_count = 0U;
  host->history_start = 0U;
  host->history_count = 0U;
  memset(host->history, 0, sizeof(host->history));
  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;
  host->state_file_path[0] = '\0';
  host_state_resolve_path(host);
  pthread_mutex_init(&host->lock, NULL);

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
  snprintf(host->motd, sizeof(host->motd), "%s", motd);
  pthread_mutex_unlock(&host->lock);
}

static bool string_contains_case_insensitive(const char *haystack, const char *needle) {
  if (haystack == NULL || needle == NULL || needle[0] == '\0') {
    return false;
  }

  const size_t needle_len = strlen(needle);
  for (const char *cursor = haystack; *cursor != '\0'; ++cursor) {
    if (strncasecmp(cursor, needle, needle_len) == 0) {
      return true;
    }
  }

  return false;
}

static void session_send_pre_handshake_notice(ssh_session session, const char *message) {
  if (session == NULL || message == NULL || message[0] == '\0') {
    return;
  }

  const size_t length = strlen(message);
  if (length == 0U) {
    return;
  }

  const int fd = ssh_get_fd(session);
  if (fd < 0) {
    return;
  }

#if defined(MSG_NOSIGNAL)
  (void)send(fd, message, length, MSG_NOSIGNAL);
#else
  (void)send(fd, message, length, 0);
#endif
}

static bool host_error_indicates_hostkey_mismatch(const char *error_message) {
  if (error_message == NULL || error_message[0] == '\0') {
    return false;
  }

  static const char *const kNeedles[] = {
      "no match for method",
      "host key",
      "hostkey",
  };

  for (size_t idx = 0; idx < sizeof(kNeedles) / sizeof(kNeedles[0]); ++idx) {
    if (string_contains_case_insensitive(error_message, kNeedles[idx])) {
      return true;
    }
  }

  return false;
}

int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory) {
  if (host == NULL) {
    errno = EINVAL;
    return -1;
  }

  const char *address = bind_addr != NULL ? bind_addr : "0.0.0.0";
  const char *bind_port = port != NULL ? port : "2222";
  const char *default_key_filename = "ssh_host_rsa_key";
  const char *host_key_path = NULL;
  char resolved_host_key[PATH_MAX];

  if (key_directory != NULL && key_directory[0] != '\0') {
    struct stat key_path_info;
    const bool stat_ok = stat(key_directory, &key_path_info) == 0;
    if (stat_ok && !S_ISDIR(key_path_info.st_mode)) {
      host_key_path = key_directory;
    } else {
      const size_t dir_len = strlen(key_directory);
      const bool needs_separator = dir_len > 0U && key_directory[dir_len - 1U] != '/';
      int written =
          snprintf(resolved_host_key, sizeof(resolved_host_key), "%s%s%s", key_directory,
                   needs_separator ? "/" : "", default_key_filename);
      if (written < 0 || (size_t)written >= sizeof(resolved_host_key)) {
        humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
        errno = ENAMETOOLONG;
        return -1;
      }
      host_key_path = resolved_host_key;
    }

    if (host_key_path == NULL) {
      humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
      errno = ENAMETOOLONG;
      return -1;
    }

    if (access(host_key_path, R_OK) != 0) {
      const int access_error = errno != 0 ? errno : ENOENT;
      char error_message[PATH_MAX + 64];
      snprintf(error_message, sizeof(error_message), "host key not accessible at %s", host_key_path);
      humanized_log_error("host", error_message, access_error);
      errno = access_error;
      return -1;
    }
  } else {
    const char *candidates[] = {default_key_filename, "/var/lib/ssh-chatter/ssh_host_rsa_key",
                                "/etc/ssh-chatter/ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key"};
    for (size_t idx = 0; idx < sizeof(candidates) / sizeof(candidates[0]); ++idx) {
      if (access(candidates[idx], R_OK) == 0) {
        host_key_path = candidates[idx];
        break;
      }
    }

    if (host_key_path == NULL) {
      humanized_log_error("host", "unable to locate host key", ENOENT);
      errno = ENOENT;
      return -1;
    }
  }

  if (access(host_key_path, R_OK) != 0) {
    const int access_error = errno != 0 ? errno : ENOENT;
    char error_message[PATH_MAX + 64];
    snprintf(error_message, sizeof(error_message), "unable to access host key at %s", host_key_path);
    humanized_log_error("host", error_message, access_error);
    errno = access_error;
    return -1;
  }

  ssh_bind bind_handle = ssh_bind_new();
  if (bind_handle == NULL) {
    humanized_log_error("host", "failed to allocate ssh_bind", ENOMEM);
    errno = ENOMEM;
    return -1;
  }

  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);

  ssh_key imported_key = NULL;
  if (ssh_pki_import_privkey_file(host_key_path, NULL, NULL, NULL, &imported_key) != SSH_OK ||
      imported_key == NULL) {
    const int import_error = errno != 0 ? errno : EIO;
    humanized_log_error("host", "failed to import host key", import_error);
    ssh_bind_free(bind_handle);
    errno = import_error;
    return -1;
  }

  const ssh_keytypes_e key_type = ssh_key_type(imported_key);
  const char *host_key_type = host_key_type_to_name(key_type);
  if (host_key_type == NULL) {
    ssh_key_free(imported_key);
    humanized_log_error("host", "unsupported host key type", ENOTSUP);
    ssh_bind_free(bind_handle);
    errno = ENOTSUP;
    return -1;
  }

  bool using_legacy_key = false;

  errno = 0;
  if (ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_HOSTKEY, host_key_type) != SSH_OK) {
    const int option_error = errno;
    const char *error_message = ssh_get_error(bind_handle);
    const bool unsupported_option =
        host_option_is_unsupported(error_message, option_error, host_key_path);
    if (!unsupported_option ||
        !host_configure_legacy_host_key(bind_handle, key_type, host_key_path)) {
      ssh_key_free(imported_key);
      const int effective_error = option_error != 0 ? option_error : EIO;
      humanized_log_error("host",
                          (error_message != NULL && error_message[0] != '\0') ? error_message : NULL,
                          effective_error);
      ssh_bind_free(bind_handle);
      errno = effective_error;
      return -1;
    }

    using_legacy_key = true;
  }

  if (!using_legacy_key) {
    errno = 0;
    if (ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_IMPORT_KEY, imported_key) != SSH_OK) {
      const int option_error = errno;
      const char *error_message = ssh_get_error(bind_handle);
      const bool unsupported_option =
          host_option_is_unsupported(error_message, option_error, host_key_path);
      if (!unsupported_option ||
          !host_configure_legacy_host_key(bind_handle, key_type, host_key_path)) {
        ssh_key_free(imported_key);
        const int effective_error = option_error != 0 ? option_error : EIO;
        humanized_log_error("host",
                            (error_message != NULL && error_message[0] != '\0') ? error_message : NULL,
                            effective_error);
        ssh_bind_free(bind_handle);
        errno = effective_error;
        return -1;
      }

      using_legacy_key = true;
    }
  }

  ssh_key_free(imported_key);

  if (ssh_bind_listen(bind_handle) < 0) {
    humanized_log_error("host", ssh_get_error(bind_handle), EIO);
    ssh_bind_free(bind_handle);
    errno = EIO;
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
      const char *error_message = ssh_get_error(session);
      if (host_error_indicates_hostkey_mismatch(error_message)) {
        static const char *kRsaNotice =
            "RSA host keys are required; please regenerate your personal RSA key and reconnect.\r\n";
        session_send_pre_handshake_notice(session, kRsaNotice);
      }

      humanized_log_error("host", error_message != NULL ? error_message : "key exchange failed", EPROTO);
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
