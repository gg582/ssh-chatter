#ifndef SSH_CHATTER_HOST_H
#define SSH_CHATTER_HOST_H

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "theme.h"

#define SSH_CHATTER_MESSAGE_LIMIT 1024
#define SSH_CHATTER_MAX_USERS 1024
#define SSH_CHATTER_MAX_INPUT_LEN 1024
#define SSH_CHATTER_USERNAME_LEN 24
#define SSH_CHATTER_IP_LEN 64
#define SSH_CHATTER_COLOR_NAME_LEN 32
#define SSH_CHATTER_MAX_BANS 128
#define SSH_CHATTER_HISTORY_LIMIT 64
#define SSH_CHATTER_INPUT_HISTORY_LIMIT 64
#define SSH_CHATTER_SCROLLBACK_CHUNK 32
#define SSH_CHATTER_MAX_PREFERENCES 1024
#define SSH_CHATTER_ATTACHMENT_TARGET_LEN 256
#define SSH_CHATTER_ATTACHMENT_CAPTION_LEN 256
#define SSH_CHATTER_REACTION_KIND_COUNT 7

struct host;
struct session_ctx;

typedef struct chat_user {
  char name[SSH_CHATTER_USERNAME_LEN];
  bool is_operator;
  bool is_lan_operator;
} chat_user_t;

typedef struct chat_room {
  pthread_mutex_t lock;
  struct session_ctx *members[SSH_CHATTER_MAX_USERS];
  size_t member_count;
} chat_room_t;

typedef enum chat_attachment_type {
  CHAT_ATTACHMENT_NONE = 0,
  CHAT_ATTACHMENT_IMAGE,
  CHAT_ATTACHMENT_VIDEO,
  CHAT_ATTACHMENT_AUDIO,
  CHAT_ATTACHMENT_FILE,
} chat_attachment_type_t;

typedef struct chat_history_entry {
  bool is_user_message;
  char message[SSH_CHATTER_MESSAGE_LIMIT];
  char username[SSH_CHATTER_USERNAME_LEN];
  const char *user_color_code;
  const char *user_highlight_code;
  bool user_is_bold;
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  uint64_t message_id;
  chat_attachment_type_t attachment_type;
  char attachment_target[SSH_CHATTER_ATTACHMENT_TARGET_LEN];
  char attachment_caption[SSH_CHATTER_ATTACHMENT_CAPTION_LEN];
  uint32_t reaction_counts[SSH_CHATTER_REACTION_KIND_COUNT];
} chat_history_entry_t;

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
  char input_buffer[SSH_CHATTER_MAX_INPUT_LEN];
  size_t input_length;
  char input_history[SSH_CHATTER_INPUT_HISTORY_LIMIT][SSH_CHATTER_MAX_INPUT_LEN];
  size_t input_history_count;
  int input_history_position;
  bool input_escape_active;
  char input_escape_buffer[8];
  size_t input_escape_length;
  char client_ip[SSH_CHATTER_IP_LEN];
  const char *user_color_code;
  const char *user_highlight_code;
  bool user_is_bold;
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  const char *system_fg_code;
  const char *system_bg_code;
  const char *system_highlight_code;
  bool system_is_bold;
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  bool should_exit;
  bool username_conflict;
  bool has_joined_room;
  size_t history_scroll_position;
} session_ctx_t;

typedef struct user_preference {
  bool in_use;
  bool has_user_theme;
  bool has_system_theme;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  bool user_is_bold;
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  bool system_is_bold;
} user_preference_t;

typedef struct host {
  chat_room_t room;
  ssh_listener_t listener;
  auth_profile_t *auth;
  UserTheme user_theme;
  SystemTheme system_theme;
  char default_user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char default_user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char default_system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char default_system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char default_system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  struct {
    char username[SSH_CHATTER_USERNAME_LEN];
    char ip[SSH_CHATTER_IP_LEN];
  } bans[SSH_CHATTER_MAX_BANS];
  size_t ban_count;
  char version[64];
  char motd[1024];
  size_t connection_count;
  chat_history_entry_t history[SSH_CHATTER_HISTORY_LIMIT];
  size_t history_start;
  size_t history_count;
  uint64_t next_message_id;
  user_preference_t preferences[SSH_CHATTER_MAX_PREFERENCES];
  size_t preference_count;
  pthread_mutex_t lock;
  char state_file_path[PATH_MAX];
} host_t;

void host_init(host_t *host, auth_profile_t *auth);
void host_set_motd(host_t *host, const char *motd);
int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory);

#endif
