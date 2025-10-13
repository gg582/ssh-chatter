#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "host.h"

#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "humanized/humanized.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

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

static void trim_whitespace_inplace(char *text);
static const char *lookup_color_code(const color_entry_t *entries, size_t entry_count, const char *name);
static bool parse_bool_token(const char *token, bool *value);
static void session_send_line(ssh_channel channel, const char *message);
static bool chat_room_get_user_ip(chat_room_t *room, const char *username, char *ip_buffer, size_t buffer_len);
static void session_dispatch_command(session_ctx_t *ctx, const char *line);

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

  char formatted[SSH_CHATTER_MESSAGE_LIMIT + SSH_CHATTER_USERNAME_LEN + 4U];
  if (from != NULL) {
    snprintf(formatted, sizeof(formatted), "%s: %s", from->user.name, message);
  } else {
    snprintf(formatted, sizeof(formatted), "%s", message);
  }

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    session_send_line(member->channel, formatted);
  }

  if (from != NULL) {
    printf("[broadcast:%s] %s\n", from->user.name, message);
  } else {
    printf("[broadcast] %s\n", message);
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

static int session_authenticate(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool authenticated = false;

  while (!authenticated && (message = ssh_message_get(ctx->session)) != NULL) {
    switch (ssh_message_type(message)) {
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
    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
        ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
      ctx->channel = ssh_message_channel_request_open_reply_accept(message);
      ssh_message_free(message);
      break;
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
  session_send_line(ctx->channel, "/ban <username>    - ban a user (operator only)");
  session_send_line(ctx->channel, "/poke <username>   - send a bell to a user");
  session_send_line(ctx->channel, "/color (text;highlight[;bold]) - preview chat colors");
  session_send_line(ctx->channel,
                    "  ex: /color (green;grey;bold) or /color (green;grey)");
  session_send_line(ctx->channel, "Regular messages are broadcast to everyone.");
}

static void session_echo_input(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || ctx->channel == NULL || line == NULL) {
    return;
  }

  char echo_buffer[SSH_CHATTER_MESSAGE_LIMIT + SSH_CHATTER_USERNAME_LEN + 4U];
  if (line[0] == '/') {
    snprintf(echo_buffer, sizeof(echo_buffer), "%s", line);
  } else {
    snprintf(echo_buffer, sizeof(echo_buffer), "%s: %s", ctx->user.name, line);
  }

  session_send_line(ctx->channel, echo_buffer);
}

static void session_process_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL || line[0] == '\0') {
    return;
  }

  printf("[%s] %s\n", ctx->user.name, line);

  session_echo_input(ctx, line);

  if (line[0] == '/') {
    session_dispatch_command(ctx, line);
  } else {
    chat_room_broadcast(&ctx->owner->room, line, ctx);
  }
}

static void session_handle_ban(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_line(ctx->channel, "You are not allowed to ban users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_line(ctx->channel, "Usage: /ban <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_line(ctx->channel, "Usage: /ban <username>");
    return;
  }

  char target_ip[SSH_CHATTER_IP_LEN];
  if (!chat_room_get_user_ip(&ctx->owner->room, target_name, target_ip, sizeof(target_ip))) {
    char not_found[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
    session_send_line(ctx->channel, not_found);
    return;
  }

  const char *ip_for_log = target_ip[0] != '\0' ? target_ip : "unknown";

  printf("[ban] %s requested IP ban for %s (%s)\n", ctx->user.name, target_name, ip_for_log);

  char response[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(response, sizeof(response),
           "Ban command recorded for %s at %s (TODO: enforce IP ban).", target_name, ip_for_log);
  session_send_line(ctx->channel, response);
}

static void session_handle_poke(session_ctx_t *ctx, const char *arguments) {
  if (arguments == NULL || *arguments == '\0') {
    session_send_line(ctx->channel, "Usage: /poke <username>");
    return;
  }

  printf("[poke] %s pokes %s\n", ctx->user.name, arguments);
  session_send_line(ctx->channel, "Poke command recorded (TODO: implement).");
}

static void session_handle_color(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_line(ctx->channel, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_line(ctx->channel, "Usage: /color (text;highlight[;bold])");
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
      session_send_line(ctx->channel, "Usage: /color (text;highlight[;bold])");
      return;
    }
    working[len - 1U] = '\0';
    trim_whitespace_inplace(working);
  }

  if (working[0] == '\0') {
    session_send_line(ctx->channel, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char *tokens[3] = {0};
  size_t token_count = 0U;
  bool extra_tokens = false;
  char *cursor = working;

  while (cursor != NULL) {
    char *next = strchr(cursor, ';');
    if (next != NULL) {
      *next = '\0';
    }

    trim_whitespace_inplace(cursor);

    if (cursor[0] == '\0') {
      session_send_line(ctx->channel, "Each color field must be provided.");
      return;
    }

    if (token_count < 3U) {
      tokens[token_count++] = cursor;
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

  if (extra_tokens || token_count < 2U || token_count > 3U) {
    session_send_line(ctx->channel, "Usage: /color (text;highlight[;bold])");
    return;
  }

  const char *text_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), tokens[0]);
  if (text_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown text color '%s'.", tokens[0]);
    session_send_line(ctx->channel, message);
    return;
  }

  const char *highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                tokens[1]);
  if (highlight_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown highlight color '%s'.", tokens[1]);
    session_send_line(ctx->channel, message);
    return;
  }

  bool is_bold = false;
  if (token_count == 3U) {
    if (!parse_bool_token(tokens[2], &is_bold)) {
      session_send_line(ctx->channel, "The third value must describe bold (ex: bold, true, normal).");
      return;
    }
  }

  ctx->owner->user_theme.userColor = text_code;
  ctx->owner->user_theme.highlight = highlight_code;
  ctx->owner->user_theme.isBold = is_bold;

  char info[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(info, sizeof(info), "Applied colors: text=%s highlight=%s bold=%s", tokens[0], tokens[1],
           is_bold ? "on" : "off");
  session_send_line(ctx->channel, info);

  const char *bold_code = is_bold ? ANSI_BOLD : "";
  char preview[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(preview, sizeof(preview), "%s%s%ssh-chatter color preview%s", highlight_code, bold_code, text_code,
           ANSI_RESET);
  session_send_line(ctx->channel, preview);
}

static bool chat_room_get_user_ip(chat_room_t *room, const char *username, char *ip_buffer, size_t buffer_len) {
  if (room == NULL || username == NULL) {
    return false;
  }

  bool found = false;
  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    session_ctx_t *member = room->members[idx];
    if (member == NULL) {
      continue;
    }

    if (strncmp(member->user.name, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      if (ip_buffer != NULL && buffer_len > 0U) {
        if (member->client_ip[0] != '\0') {
          snprintf(ip_buffer, buffer_len, "%s", member->client_ip);
        } else {
          ip_buffer[0] = '\0';
        }
      }
      found = true;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);

  return found;
}

static void session_dispatch_command(session_ctx_t *ctx, const char *line) {
  if (strncmp(line, "/help", 5) == 0) {
    session_print_help(ctx);
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

  char broadcast_buffer[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(broadcast_buffer, sizeof(broadcast_buffer), "%s", line);
  chat_room_broadcast(&ctx->owner->room, broadcast_buffer, ctx);
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

  chat_room_add(&ctx->owner->room, ctx);
  printf("[join] %s\n", ctx->user.name);

  if (ctx->owner->motd[0] != '\0') {
    session_send_line(ctx->channel, ctx->owner->motd);
  }

  char join_message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(join_message, sizeof(join_message), "* %s has joined the chat", ctx->user.name);
  chat_room_broadcast(&ctx->owner->room, join_message, NULL);

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));
  char buffer[SSH_CHATTER_MAX_INPUT_LEN];
  while (true) {
    const int bytes_read = ssh_channel_read(ctx->channel, buffer, sizeof(buffer) - 1U, 0);
    if (bytes_read <= 0) {
      break;
    }

    for (int idx = 0; idx < bytes_read; ++idx) {
      const char ch = buffer[idx];

      if (ch == '\r' || ch == '\n') {
        if (ctx->input_length > 0U) {
          ctx->input_buffer[ctx->input_length] = '\0';
          session_process_line(ctx, ctx->input_buffer);
          ctx->input_length = 0U;
        }
        continue;
      }

      if (ctx->input_length + 1U >= sizeof(ctx->input_buffer)) {
        ctx->input_buffer[sizeof(ctx->input_buffer) - 1U] = '\0';
        session_process_line(ctx, ctx->input_buffer);
        ctx->input_length = 0U;
      }

      ctx->input_buffer[ctx->input_length++] = ch;
    }
  }

  if (ctx->input_length > 0U) {
    ctx->input_buffer[ctx->input_length] = '\0';
    session_process_line(ctx, ctx->input_buffer);
    ctx->input_length = 0U;
  }

  printf("[part] %s\n", ctx->user.name);
  char part_message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(part_message, sizeof(part_message), "* %s has left the chat", ctx->user.name);
  chat_room_broadcast(&ctx->owner->room, part_message, NULL);
  chat_room_remove(&ctx->owner->room, ctx);
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
  host->user_theme.highlight = "";
  host->user_theme.isBold = false;
  host->system_theme.backgroundColor = ANSI_BLUE;
  host->system_theme.foregroundColor = ANSI_WHITE;
  host->system_theme.highlightColor = ANSI_YELLOW;
  host->system_theme.isBold = true;
  snprintf(host->version, sizeof(host->version), "ssh-chatter (C)");
  snprintf(host->motd, sizeof(host->motd), "Welcome to ssh-chat (C edition)");
  host->connection_count = 0U;
  pthread_mutex_init(&host->lock, NULL);
}

void host_set_motd(host_t *host, const char *motd) {
  if (host == NULL || motd == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  snprintf(host->motd, sizeof(host->motd), "%s", motd);
  pthread_mutex_unlock(&host->lock);
}

int host_serve(host_t *host, const char *bind_addr, const char *port) {
  if (host == NULL) {
    return -1;
  }

  const char *address = bind_addr != NULL ? bind_addr : "0.0.0.0";
  const char *bind_port = port != NULL ? port : "2222";

  ssh_bind bind_handle = ssh_bind_new();
  if (bind_handle == NULL) {
    humanized_log_error("host", "failed to allocate ssh_bind", ENOMEM);
    return -1;
  }

  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

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
