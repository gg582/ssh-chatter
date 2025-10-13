#ifndef SSH_CHATTER_HOST_H
#define SSH_CHATTER_HOST_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "theme.h"

#define SSH_CHATTER_MESSAGE_LIMIT 512
#define SSH_CHATTER_MAX_USERS 512
#define SSH_CHATTER_MAX_INPUT_LEN 1024
#define SSH_CHATTER_USERNAME_LEN 24

struct host;
struct session_ctx;

typedef struct chat_user {
  char name[SSH_CHATTER_USERNAME_LEN];
  bool is_operator;
} chat_user_t;

typedef struct chat_room {
  pthread_mutex_t lock;
  struct session_ctx *members[SSH_CHATTER_MAX_USERS];
  size_t member_count;
} chat_room_t;

typedef struct auth_profile {
  bool is_banned;
  bool is_operator;
  bool is_observer;
} auth_profile_t;

typedef struct ssh_listener {
  ssh_bind handle;
} ssh_listener_t;

typedef struct session_ctx {
  ssh_session session;
  ssh_channel channel;
  chat_user_t user;
  auth_profile_t auth;
  struct host *owner;
} session_ctx_t;

typedef struct host {
  chat_room_t room;
  ssh_listener_t listener;
  auth_profile_t *auth;
  UserTheme user_theme;
  SystemTheme system_theme;
  char version[64];
  char motd[256];
  size_t connection_count;
  pthread_mutex_t lock;
} host_t;

void host_init(host_t *host, auth_profile_t *auth);
void host_set_motd(host_t *host, const char *motd);
int host_serve(host_t *host, const char *bind_addr, const char *port);

#endif
