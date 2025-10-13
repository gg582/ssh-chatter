#include "host.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "humanized/humanized.h"

static void session_send_line(ssh_channel channel, const char *message);
static void session_dispatch_command(session_ctx_t *ctx, const char *line);
static void session_process_line(session_ctx_t *ctx, const char *line);

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

static void chat_room_broadcast(chat_room_t *room, const char *message, const chat_user_t *from) {
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
    if (target_count < SSH_CHATTER_MAX_USERS) {
      targets[target_count++] = member;
    }
  }
  pthread_mutex_unlock(&room->lock);

  char formatted[SSH_CHATTER_MESSAGE_LIMIT + SSH_CHATTER_USERNAME_LEN + 4U];
  if (from != NULL) {
    snprintf(formatted, sizeof(formatted), "%s: %s", from->name, message);
  } else {
    snprintf(formatted, sizeof(formatted), "%s", message);
  }

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    session_send_line(member->channel, formatted);
  }

  if (from != NULL) {
    printf("[broadcast:%s] %s\n", from->name, message);
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
  session_send_line(ctx->channel, "Regular messages are broadcast to everyone.");
}

static void session_process_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL || line[0] == '\0') {
    return;
  }

  printf("[%s] %s\n", ctx->user.name, line);

  if (line[0] == '/') {
    session_dispatch_command(ctx, line);
  } else {
    chat_room_broadcast(&ctx->owner->room, line, &ctx->user);
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

  printf("[ban] %s requested ban for %s\n", ctx->user.name, arguments);
  session_send_line(ctx->channel, "Ban command recorded (TODO: implement).");
}

static void session_handle_poke(session_ctx_t *ctx, const char *arguments) {
  if (arguments == NULL || *arguments == '\0') {
    session_send_line(ctx->channel, "Usage: /poke <username>");
    return;
  }

  printf("[poke] %s pokes %s\n", ctx->user.name, arguments);
  session_send_line(ctx->channel, "Poke command recorded (TODO: implement).");
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

  char broadcast_buffer[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(broadcast_buffer, sizeof(broadcast_buffer), "%s", line);
  chat_room_broadcast(&ctx->owner->room, broadcast_buffer, &ctx->user);
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
  host->user_theme.highlight = ANSI_BOLD;
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
