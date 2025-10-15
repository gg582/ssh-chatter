#ifndef SSH_CHATTER_HOST_H
#define SSH_CHATTER_HOST_H

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "theme.h"

#define SSH_CHATTER_SOUND_URL_LEN 1024
#define SSH_CHATTER_MESSAGE_LIMIT 1024
#define SSH_CHATTER_MAX_INPUT_LEN 1024
#define SSH_CHATTER_USERNAME_LEN 24
#define SSH_CHATTER_IP_LEN 64
#define SSH_CHATTER_COLOR_NAME_LEN 32
#define SSH_CHATTER_MAX_BANS 128
#define SSH_CHATTER_HISTORY_LIMIT 64
#define SSH_CHATTER_INPUT_HISTORY_LIMIT 64
#define SSH_CHATTER_SCROLLBACK_CHUNK 64
#define SSH_CHATTER_MAX_PREFERENCES 1024
#define SSH_CHATTER_ATTACHMENT_TARGET_LEN 256
#define SSH_CHATTER_ATTACHMENT_CAPTION_LEN 256
#define SSH_CHATTER_REACTION_KIND_COUNT 7
#define SSH_CHATTER_OS_NAME_LEN 16
#define SSH_CHATTER_POLL_LABEL_LEN 32
#define SSH_CHATTER_MAX_NAMED_POLLS 16
#define SSH_CHATTER_MAX_NAMED_VOTERS 256
#define SSH_CHATTER_BBS_MAX_POSTS 128
#define SSH_CHATTER_BBS_TITLE_LEN 96
#define SSH_CHATTER_BBS_BODY_LEN 2048
#define SSH_CHATTER_BBS_TAG_LEN 24
#define SSH_CHATTER_BBS_MAX_TAGS 4
#define SSH_CHATTER_BBS_MAX_COMMENTS 64
#define SSH_CHATTER_BBS_COMMENT_LEN 512
#define SSH_CHATTER_MAX_GRANTS 128
#define SSH_CHATTER_JOIN_BAR_MAX 17

struct host;
struct session_ctx;
struct client_manager;
struct chat_bot;
struct webssh_client;

typedef struct join_activity_entry {
  char ip[SSH_CHATTER_IP_LEN];
  char last_username[SSH_CHATTER_USERNAME_LEN];
  struct timespec last_attempt;
  size_t rapid_attempts;
  size_t same_name_attempts;
} join_activity_entry_t;

typedef struct client_manager client_manager_t;
typedef struct chat_bot chat_bot_t;
typedef struct webssh_client webssh_client_t;

typedef struct chat_user {
  char name[SSH_CHATTER_USERNAME_LEN];
  bool is_operator;
  bool is_lan_operator;
} chat_user_t;

typedef struct chat_room {
  pthread_mutex_t lock;
  struct session_ctx **members;
  size_t member_count;
  size_t member_capacity;
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
  struct timespec last_message_time;
  bool has_last_message_time;
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int daily_year;
  int daily_yday;
  char daily_function[64];
  bool in_bbs_mode;
  bool has_birthday;
  char birthday[16];
  bool bbs_post_pending;
  char pending_bbs_title[SSH_CHATTER_BBS_TITLE_LEN];
  char pending_bbs_tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
  size_t pending_bbs_tag_count;
  char pending_bbs_body[SSH_CHATTER_BBS_BODY_LEN];
  size_t pending_bbs_body_length;
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
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int daily_year;
  int daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int last_poll_choice;
  bool has_birthday;
  char birthday[16];
  struct {
    char label[SSH_CHATTER_POLL_LABEL_LEN];
    uint64_t poll_id;
    int choice;
  } named_votes[SSH_CHATTER_MAX_NAMED_POLLS];
} user_preference_t;

typedef struct poll_option {
  char text[SSH_CHATTER_MESSAGE_LIMIT];
  uint32_t votes;
} poll_option_t;

typedef struct poll_state {
  bool active;
  uint64_t id;
  char question[SSH_CHATTER_MESSAGE_LIMIT];
  size_t option_count;
  poll_option_t options[5];
} poll_state_t;

typedef struct named_poll_state {
  poll_state_t poll;
  char label[SSH_CHATTER_POLL_LABEL_LEN];
  char owner[SSH_CHATTER_USERNAME_LEN];
  struct {
    char username[SSH_CHATTER_USERNAME_LEN];
    int choice;
  } voters[SSH_CHATTER_MAX_NAMED_VOTERS];
  size_t voter_count;
} named_poll_state_t;

typedef struct bbs_comment {
  char author[SSH_CHATTER_USERNAME_LEN];
  char text[SSH_CHATTER_BBS_COMMENT_LEN];
  time_t created_at;
} bbs_comment_t;

typedef struct bbs_post {
  bool in_use;
  uint64_t id;
  char author[SSH_CHATTER_USERNAME_LEN];
  char title[SSH_CHATTER_BBS_TITLE_LEN];
  char body[SSH_CHATTER_BBS_BODY_LEN];
  char tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
  size_t tag_count;
  time_t created_at;
  time_t bumped_at;
  bbs_comment_t comments[SSH_CHATTER_BBS_MAX_COMMENTS];
  size_t comment_count;
} bbs_post_t;

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
  char motd[4096];
  size_t connection_count;
  chat_history_entry_t history[SSH_CHATTER_HISTORY_LIMIT];
  size_t history_start;
  size_t history_count;
  uint64_t next_message_id;
  user_preference_t preferences[SSH_CHATTER_MAX_PREFERENCES];
  size_t preference_count;
  pthread_mutex_t lock;
  char state_file_path[PATH_MAX];
  poll_state_t poll;
  named_poll_state_t named_polls[SSH_CHATTER_MAX_NAMED_POLLS];
  size_t named_poll_count;
  bbs_post_t bbs_posts[SSH_CHATTER_BBS_MAX_POSTS];
  size_t bbs_post_count;
  uint64_t next_bbs_id;
  bool random_seeded;
  client_manager_t *clients;
  chat_bot_t *bot;
  webssh_client_t *web_client;
  struct {
    char ip[SSH_CHATTER_IP_LEN];
  } operator_grants[SSH_CHATTER_MAX_GRANTS];
  size_t operator_grant_count;
  struct timespec next_join_ready_time;
  bool join_throttle_initialised;
  size_t join_progress_length;
  join_activity_entry_t *join_activity;
  size_t join_activity_count;
  size_t join_activity_capacity;
  bool has_last_captcha;
  char last_captcha_question[256];
  char last_captcha_answer[64];
  struct timespec last_captcha_generated;
} host_t;

void host_init(host_t *host, auth_profile_t *auth);
void host_set_motd(host_t *host, const char *motd);
int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory);
bool host_post_client_message(host_t *host, const char *username, const char *message, const char *color_name,
                             const char *highlight_name, bool is_bold);
void host_shutdown(host_t *host);
bool host_snapshot_last_captcha(host_t *host, char *question, size_t question_length, char *answer,
                               size_t answer_length, struct timespec *timestamp);

#endif
