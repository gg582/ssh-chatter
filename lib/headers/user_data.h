#ifndef SSH_CHATTER_USER_DATA_H
#define SSH_CHATTER_USER_DATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef USER_DATA_MAILBOX_LIMIT
#define USER_DATA_MAILBOX_LIMIT 32U
#endif

#ifndef USER_DATA_MAILBOX_MESSAGE_LEN
#define USER_DATA_MAILBOX_MESSAGE_LEN 256U
#endif

#ifndef USER_DATA_PROFILE_PICTURE_LEN
#define USER_DATA_PROFILE_PICTURE_LEN 20480U
#endif

#ifndef USER_DATA_FLAG_HISTORY_LIMIT
#define USER_DATA_FLAG_HISTORY_LIMIT 16U
#endif

#ifndef SSH_CHATTER_USERNAME_LEN
#error "SSH_CHATTER_USERNAME_LEN must be defined before including user_data.h"
#endif

typedef struct user_data_mail_entry {
  uint64_t timestamp;
  char sender[SSH_CHATTER_USERNAME_LEN];
  char message[USER_DATA_MAILBOX_MESSAGE_LEN];
} user_data_mail_entry_t;

typedef struct alpha_centauri_save {
  uint8_t active;
  uint8_t stage;
  uint8_t eva_ready;
  uint8_t awaiting_flag;
  double velocity_fraction_c;
  double distance_travelled_ly;
  double distance_remaining_ly;
  double fuel_percent;
  double oxygen_days;
  double mission_time_years;
  double radiation_msv;
} alpha_centauri_save_t;

typedef struct user_data_record {
  uint32_t magic;
  uint32_t version;
  char username[SSH_CHATTER_USERNAME_LEN];
  uint32_t mailbox_count;
  user_data_mail_entry_t mailbox[USER_DATA_MAILBOX_LIMIT];
  char profile_picture[USER_DATA_PROFILE_PICTURE_LEN];
  alpha_centauri_save_t alpha;
  uint32_t flag_count;
  uint32_t flag_history_count;
  uint64_t flag_history[USER_DATA_FLAG_HISTORY_LIMIT];
  uint64_t last_updated;
  uint8_t reserved[64];
} user_data_record_t;

bool user_data_sanitize_username(const char *username, char *sanitized, size_t length);
bool user_data_path_for(const char *root, const char *username, char *path, size_t length);
bool user_data_ensure_root(const char *root);
bool user_data_init(user_data_record_t *record, const char *username);
bool user_data_load(const char *root, const char *username, user_data_record_t *record);
bool user_data_save(const char *root, const user_data_record_t *record);
bool user_data_ensure_exists(const char *root, const char *username, user_data_record_t *record);

#endif /* SSH_CHATTER_USER_DATA_H */
