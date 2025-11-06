#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "headers/host.h"
#include "headers/user_data.h"

#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define USER_DATA_MAGIC 0x4D424F58U /* 'MBOX' */
#define USER_DATA_VERSION 5U
#define USER_DATA_VERSION_V4 4U
#define USER_DATA_VERSION_V3 3U
#define USER_DATA_VERSION_V2 2U
#define USER_DATA_VERSION_LEGACY 1U

#define USER_DATA_PROFILE_PICTURE_V1_LEN 512U
#define USER_DATA_PROFILE_PICTURE_V2_LEN 4096U
#define USER_DATA_PROFILE_PICTURE_V3_LEN 10240U

#define USER_DATA_PROFILE_DIRECTORY "profiles"
#define USER_DATA_VARIANT_LIMIT 32U

static bool user_data_profile_directory_path (const char *root, char *path,
                                              size_t length);
static bool user_data_profile_picture_path (const char *root,
                                            const char *username, char *path,
                                            size_t length);
static void user_data_profile_picture_overlay (const char *root,
                                               const char *username,
                                               user_data_record_t *record);
static bool user_data_profile_picture_store (const char *root,
                                             const user_data_record_t *record);

static size_t user_data_column_reset_sequence_length (const char *text);

typedef struct user_data_record_v1 {
  uint32_t magic;
  uint32_t version;
  char username[SSH_CHATTER_USERNAME_LEN];
  uint32_t mailbox_count;
  user_data_mail_entry_t mailbox[USER_DATA_MAILBOX_LIMIT];
  char profile_picture[USER_DATA_PROFILE_PICTURE_V1_LEN];
  alpha_centauri_save_t alpha;
  uint32_t flag_count;
  uint32_t flag_history_count;
  uint64_t flag_history[USER_DATA_FLAG_HISTORY_LIMIT];
  uint64_t last_updated;
  uint8_t reserved[64];
} user_data_record_v1_t;

typedef struct user_data_record_v2 {
  uint32_t magic;
  uint32_t version;
  char username[SSH_CHATTER_USERNAME_LEN];
  uint32_t mailbox_count;
  user_data_mail_entry_t mailbox[USER_DATA_MAILBOX_LIMIT];
  char profile_picture[USER_DATA_PROFILE_PICTURE_V2_LEN];
  alpha_centauri_save_t alpha;
  uint32_t flag_count;
  uint32_t flag_history_count;
  uint64_t flag_history[USER_DATA_FLAG_HISTORY_LIMIT];
  uint64_t last_updated;
  uint8_t reserved[64];
} user_data_record_v2_t;

typedef struct user_data_record_v3 {
  uint32_t magic;
  uint32_t version;
  char username[SSH_CHATTER_USERNAME_LEN];
  uint32_t mailbox_count;
  user_data_mail_entry_t mailbox[USER_DATA_MAILBOX_LIMIT];
  char profile_picture[USER_DATA_PROFILE_PICTURE_V3_LEN];
  alpha_centauri_save_t alpha;
  uint32_t flag_count;
  uint32_t flag_history_count;
  uint64_t flag_history[USER_DATA_FLAG_HISTORY_LIMIT];
  uint64_t last_updated;
  uint8_t reserved[64];
} user_data_record_v3_t;

typedef struct user_data_record_v4 {
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
} user_data_record_v4_t;

static size_t
user_data_column_reset_sequence_length (const char *text)
{
  if (text == NULL) {
    return 0U;
  }

  if (text[0] == '\033' && text[1] == '[' && text[2] == '1' && text[3] == 'G') {
    return 4U;
  }

  if (text[0] == '[' && text[1] == '1' && text[2] == 'G') {
    return 3U;
  }

  return 0U;
}

static void
user_data_strip_column_reset (char *text)
{
  if (text == NULL || text[0] == '\0') {
    return;
  }

  char *dst = text;
  const char *src = text;
  while (*src != '\0') {
    size_t skip = user_data_column_reset_sequence_length (src);
    if (skip > 0U) {
      src += skip;
      continue;
    }

    *dst++ = *src++;
  }

  *dst = '\0';
}

static bool
user_data_is_directory (const char *path)
{
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  struct stat st;
  if (stat (path, &st) != 0) {
    return false;
  }

  return S_ISDIR (st.st_mode);
}

static bool
user_data_create_directory (const char *path)
{
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  if (user_data_is_directory (path)) {
    return true;
  }

  if (mkdir (path, 0750) == 0) {
    return true;
  }

  if (errno == EEXIST) {
    return user_data_is_directory (path);
  }

  return false;
}

static bool
user_data_ensure_parent (const char *path)
{
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  char temp[PATH_MAX];
  snprintf (temp, sizeof (temp), "%s", path);
  char *parent = dirname (temp);
  if (parent == NULL || parent[0] == '\0') {
    return false;
  }

  return user_data_create_directory (parent);
}

static bool
user_data_file_exists (const char *path)
{
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  return access (path, F_OK) == 0;
}

static bool
user_data_build_variant_name (const char *base, size_t index, char *buffer,
                              size_t length)
{
  if (buffer == NULL || length == 0U || base == NULL || base[0] == '\0') {
    return false;
  }

  int written;
  if (index == 0U) {
    written = snprintf (buffer, length, "%s", base);
  } else {
    written = snprintf (buffer, length, "%s-%zu", base, index);
  }

  return written >= 0 && (size_t)written < length;
}

static bool
user_data_load_raw (const char *path, user_data_record_t *record,
                    bool *needs_upgrade)
{
  if (record == NULL || path == NULL || path[0] == '\0') {
    return false;
  }

  FILE *fp = fopen (path, "rb");
  if (fp == NULL) {
    return false;
  }

  struct stat st;
  if (fstat (fileno (fp), &st) != 0) {
    fclose (fp);
    return false;
  }

  if (fseek (fp, 0L, SEEK_SET) != 0) {
    fclose (fp);
    return false;
  }

  if (st.st_size < 0) {
    fclose (fp);
    return false;
  }

  const size_t file_size = (size_t)st.st_size;
  const size_t expected_size = sizeof (user_data_record_t);
  const size_t v4_size = sizeof (user_data_record_v4_t);
  const size_t v3_size = sizeof (user_data_record_v3_t);
  const size_t v2_size = sizeof (user_data_record_v2_t);
  const size_t legacy_size = sizeof (user_data_record_v1_t);

  user_data_record_t temp;
  bool upgrade = false;
  bool loaded = false;

  // curent  userdata
  if (file_size == expected_size) {
    size_t read = fread (&temp, sizeof (temp), 1U, fp);
    if (read == 1U && temp.magic == USER_DATA_MAGIC
        && temp.version == USER_DATA_VERSION) {
      loaded = true;
    }
  } else if (file_size == v4_size) {
    user_data_record_v4_t legacy4;
    size_t read = fread (&legacy4, sizeof (legacy4), 1U, fp);
    if (read == 1U && legacy4.magic == USER_DATA_MAGIC
        && legacy4.version == USER_DATA_VERSION_V4) {
      memset (&temp, 0, sizeof (temp));
      temp.magic = USER_DATA_MAGIC;
      temp.version = USER_DATA_VERSION;
      snprintf (temp.username, sizeof (temp.username), "%s", legacy4.username);
      temp.last_ip[0] = '\0';
      temp.mailbox_count = legacy4.mailbox_count;
      memcpy (temp.mailbox, legacy4.mailbox, sizeof (temp.mailbox));
      memcpy (temp.profile_picture, legacy4.profile_picture,
              sizeof (legacy4.profile_picture));
      temp.alpha = legacy4.alpha;
      temp.flag_count = legacy4.flag_count;
      temp.flag_history_count = legacy4.flag_history_count;
      memcpy (temp.flag_history, legacy4.flag_history,
              sizeof (temp.flag_history));
      temp.last_updated = legacy4.last_updated;
      memset (temp.reserved, 0, sizeof (temp.reserved));
      upgrade = true;
      loaded = true;
    }
  } else if (file_size
             == v3_size) { //legacy userdata; profile picture size is different
    user_data_record_v3_t legacy3;
    size_t read = fread (&legacy3, sizeof (legacy3), 1U, fp);
    if (read == 1U && legacy3.magic == USER_DATA_MAGIC
        && legacy3.version == USER_DATA_VERSION_V3) {
      memset (&temp, 0, sizeof (temp));
      temp.magic = USER_DATA_MAGIC;
      temp.version = USER_DATA_VERSION;
      snprintf (temp.username, sizeof (temp.username), "%s", legacy3.username);
      temp.last_ip[0] = '\0';
      temp.mailbox_count = legacy3.mailbox_count;
      memcpy (temp.mailbox, legacy3.mailbox, sizeof (temp.mailbox));
      memcpy (temp.profile_picture, legacy3.profile_picture,
              sizeof (legacy3.profile_picture));
      temp.alpha = legacy3.alpha;
      temp.flag_count = legacy3.flag_count;
      temp.flag_history_count = legacy3.flag_history_count;
      memcpy (temp.flag_history, legacy3.flag_history,
              sizeof (temp.flag_history));
      temp.last_updated = legacy3.last_updated;
      memset (temp.reserved, 0, sizeof (temp.reserved));
      upgrade = true;
      loaded = true;
    }
  } else if (file_size == v2_size) {
    user_data_record_v2_t legacy2;
    size_t read = fread (&legacy2, sizeof (legacy2), 1U, fp);
    if (read == 1U && legacy2.magic == USER_DATA_MAGIC
        && legacy2.version == USER_DATA_VERSION_V2) {
      memset (&temp, 0, sizeof (temp));
      temp.magic = USER_DATA_MAGIC;
      temp.version = USER_DATA_VERSION;
      snprintf (temp.username, sizeof (temp.username), "%s", legacy2.username);
      temp.last_ip[0] = '\0';
      temp.mailbox_count = legacy2.mailbox_count;
      memcpy (temp.mailbox, legacy2.mailbox, sizeof (temp.mailbox));
      memcpy (temp.profile_picture, legacy2.profile_picture,
              sizeof (legacy2.profile_picture));
      temp.alpha = legacy2.alpha;
      temp.flag_count = legacy2.flag_count;
      temp.flag_history_count = legacy2.flag_history_count;
      memcpy (temp.flag_history, legacy2.flag_history,
              sizeof (temp.flag_history));
      temp.last_updated = legacy2.last_updated;
      memset (temp.reserved, 0, sizeof (temp.reserved));
      upgrade = true;
      loaded = true;
    }
  } else if (file_size == legacy_size) {
    user_data_record_v1_t legacy1;
    size_t read = fread (&legacy1, sizeof (legacy1), 1U, fp);
    if (read == 1U && legacy1.magic == USER_DATA_MAGIC
        && legacy1.version == USER_DATA_VERSION_LEGACY) {
      memset (&temp, 0, sizeof (temp));
      temp.magic = USER_DATA_MAGIC;
      temp.version = USER_DATA_VERSION;
      snprintf (temp.username, sizeof (temp.username), "%s", legacy1.username);
      temp.last_ip[0] = '\0';
      temp.mailbox_count = legacy1.mailbox_count;
      memcpy (temp.mailbox, legacy1.mailbox, sizeof (temp.mailbox));
      memcpy (temp.profile_picture, legacy1.profile_picture,
              sizeof (legacy1.profile_picture));
      temp.alpha = legacy1.alpha;
      temp.flag_count = legacy1.flag_count;
      temp.flag_history_count = legacy1.flag_history_count;
      memcpy (temp.flag_history, legacy1.flag_history,
              sizeof (temp.flag_history));
      temp.last_updated = legacy1.last_updated;
      memset (temp.reserved, 0, sizeof (temp.reserved));
      upgrade = true;
      loaded = true;
    }
  }

  fclose (fp);

  if (!loaded) {
    return false;
  }

  if (needs_upgrade != NULL) {
    *needs_upgrade = upgrade;
  }

  *record = temp;
  return true;
}

bool
user_data_ensure_root (const char *root)
{
  if (root == NULL || root[0] == '\0') {
    return false;
  }

  if (!user_data_create_directory (root)) {
    return false;
  }

  char profile_root[PATH_MAX];
  if (!user_data_profile_directory_path (root, profile_root,
                                         sizeof (profile_root))) {
    return false;
  }

  return user_data_create_directory (profile_root);
}

bool
user_data_sanitize_username (const char *username, char *sanitized,
                             size_t length)
{
  if (sanitized == NULL || length == 0U) {
    return false;
  }

  sanitized[0] = '\0';
  if (username == NULL || username[0] == '\0') {
    return false;
  }

  size_t out_idx = 0U;
  for (size_t idx = 0U; username[idx] != '\0'; ++idx) {
    unsigned char ch = (unsigned char)username[idx];
    if (isalnum (ch)) {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = (char)tolower (ch);
      }
    } else if (ch == '-' || ch == '_' || ch == '.') {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = (char)ch;
      }
    } else if (!isspace (ch)) {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = '_';
      }
    }
  }

  if (out_idx == 0U) {
    if (length < 5U) {
      return false;
    }
    snprintf (sanitized, length, "user");
    return true;
  }

  sanitized[out_idx] = '\0';
  return true;
}

bool
user_data_path_for (const char *root, const char *username, const char *ip,
                    bool create_if_missing, char *path, size_t length)
{
  if (path == NULL || length == 0U || root == NULL || root[0] == '\0') {
    return false;
  }

  char sanitized[SSH_CHATTER_USERNAME_LEN * 2U];
  if (!user_data_sanitize_username (username, sanitized, sizeof (sanitized))) {
    return false;
  }

  if (ip == NULL || ip[0] == '\0') {
    int written = snprintf (path, length, "%s/%s.dat", root, sanitized);
    return written >= 0 && (size_t)written < length;
  }

  size_t available_index = USER_DATA_VARIANT_LIMIT;
  char candidate_name[SSH_CHATTER_USERNAME_LEN * 2U];
  char candidate_path[PATH_MAX];
  for (size_t idx = 0U; idx < USER_DATA_VARIANT_LIMIT; ++idx) {
    if (!user_data_build_variant_name (sanitized, idx, candidate_name,
                                       sizeof (candidate_name))) {
      continue;
    }

    int written = snprintf (candidate_path, sizeof (candidate_path),
                            "%s/%s.dat", root, candidate_name);
    if (written < 0 || (size_t)written >= sizeof (candidate_path)) {
      continue;
    }

    if (user_data_file_exists (candidate_path)) {
      user_data_record_t existing;
      if (user_data_load_raw (candidate_path, &existing, NULL)) {
        bool username_match
            = strncmp (existing.username, username, sizeof (existing.username))
              == 0;
        bool ip_match = strncmp (existing.last_ip, ip, SSH_CHATTER_IP_LEN) == 0;
        bool legacy_match = existing.last_ip[0] == '\0';
        if (username_match && (ip_match || legacy_match)) {
          if ((size_t)written < length) {
            memcpy (path, candidate_path, (size_t)written + 1U);
            return true;
          }
          return false;
        }
      }
      continue;
    }

    if (available_index == USER_DATA_VARIANT_LIMIT) {
      available_index = idx;
    }
  }

  if (!create_if_missing || available_index == USER_DATA_VARIANT_LIMIT) {
    return false;
  }

  if (!user_data_build_variant_name (sanitized, available_index, candidate_name,
                                     sizeof (candidate_name))) {
    return false;
  }

  int written = snprintf (path, length, "%s/%s.dat", root, candidate_name);
  return written >= 0 && (size_t)written < length;
}

static bool
user_data_profile_directory_path (const char *root, char *path, size_t length)
{
  if (path == NULL || length == 0U || root == NULL || root[0] == '\0') {
    return false;
  }

  int written
      = snprintf (path, length, "%s/%s", root, USER_DATA_PROFILE_DIRECTORY);
  if (written < 0 || (size_t)written >= length) {
    return false;
  }

  return true;
}

static bool
user_data_profile_picture_path (const char *root, const char *username,
                                char *path, size_t length)
{
  if (path == NULL || length == 0U || root == NULL || root[0] == '\0'
      || username == NULL || username[0] == '\0') {
    return false;
  }

  char sanitized[SSH_CHATTER_USERNAME_LEN * 2U];
  if (!user_data_sanitize_username (username, sanitized, sizeof (sanitized))) {
    return false;
  }

  if (sanitized[0] == '\0') {
    return false;
  }

  char directory[PATH_MAX];
  if (!user_data_profile_directory_path (root, directory, sizeof (directory))) {
    return false;
  }

  int written = snprintf (path, length, "%s/%s.dat", directory, sanitized);
  if (written < 0 || (size_t)written >= length) {
    return false;
  }

  return true;
}

static void
user_data_profile_picture_overlay (const char *root, const char *username,
                                   user_data_record_t *record)
{
  if (record == NULL || root == NULL || root[0] == '\0' || username == NULL
      || username[0] == '\0') {
    return;
  }

  char path[PATH_MAX];
  if (!user_data_profile_picture_path (root, username, path, sizeof (path))) {
    return;
  }

  FILE *fp = fopen (path, "rb");
  if (fp == NULL) {
    return;
  }

  char buffer[USER_DATA_PROFILE_PICTURE_LEN];
  size_t read = fread (buffer, 1U, sizeof (buffer) - 1U, fp);
  if (ferror (fp) != 0) {
    fclose (fp);
    return;
  }

  fclose (fp);

  buffer[read] = '\0';
  user_data_strip_column_reset (buffer);
  buffer[USER_DATA_PROFILE_PICTURE_LEN - 1U] = '\0';
  snprintf (record->profile_picture, sizeof (record->profile_picture), "%s",
            buffer);
}

static bool
user_data_profile_picture_store (const char *root,
                                 const user_data_record_t *record)
{
  if (root == NULL || root[0] == '\0' || record == NULL
      || record->username[0] == '\0') {
    return false;
  }

  char path[PATH_MAX];
  if (!user_data_profile_picture_path (root, record->username, path,
                                       sizeof (path))) {
    return false;
  }

  if (record->profile_picture[0] == '\0') {
    if (unlink (path) == 0) {
      return true;
    }
    if (errno == ENOENT) {
      return true;
    }
    return false;
  }

  char directory[PATH_MAX];
  if (!user_data_profile_directory_path (root, directory, sizeof (directory))) {
    return false;
  }

  if (!user_data_create_directory (directory)) {
    return false;
  }

  char temp_path[PATH_MAX];
  int written = snprintf (temp_path, sizeof (temp_path), "%s.tmp", path);
  if (written < 0 || (size_t)written >= sizeof (temp_path)) {
    return false;
  }

  FILE *fp = fopen (temp_path, "wb");
  if (fp == NULL) {
    return false;
  }

  const char *picture = record->profile_picture;
  size_t remaining = strlen (picture);
  bool success = true;
  while (remaining > 0U) {
    size_t chunk = fwrite (picture, 1U, remaining, fp);
    if (chunk == 0U) {
      success = false;
      break;
    }
    picture += chunk;
    remaining -= chunk;
  }

  int error = success ? 0 : errno;
  if (success && fflush (fp) != 0) {
    success = false;
    error = errno;
  }

  if (success) {
    int fd = fileno (fp);
    if (fd >= 0 && fsync (fd) != 0) {
      success = false;
      error = errno;
    }
  }

  if (fclose (fp) != 0) {
    if (success) {
      error = errno;
    }
    success = false;
  }

  if (!success) {
    unlink (temp_path);
    errno = error != 0 ? error : EIO;
    return false;
  }

  if (rename (temp_path, path) != 0) {
    int rename_error = errno;
    unlink (temp_path);
    errno = rename_error;
    return false;
  }

  return true;
}

static void
user_data_normalize_record (user_data_record_t *record, const char *username)
{
  if (record == NULL) {
    return;
  }

  if (record->mailbox_count > USER_DATA_MAILBOX_LIMIT) {
    record->mailbox_count = USER_DATA_MAILBOX_LIMIT;
  }
  if (record->flag_history_count > USER_DATA_FLAG_HISTORY_LIMIT) {
    record->flag_history_count = USER_DATA_FLAG_HISTORY_LIMIT;
  }
  record->profile_picture[USER_DATA_PROFILE_PICTURE_LEN - 1U] = '\0';
  record->last_ip[SSH_CHATTER_IP_LEN - 1U] = '\0';
  user_data_strip_column_reset (record->profile_picture);
  if (username != NULL && username[0] != '\0') {
    snprintf (record->username, sizeof (record->username), "%s", username);
  }
}

bool
user_data_init (user_data_record_t *record, const char *username,
                const char *ip)
{
  if (record == NULL) {
    return false;
  }

  memset (record, 0, sizeof (*record));
  record->magic = USER_DATA_MAGIC;
  record->version = USER_DATA_VERSION;
  if (username != NULL) {
    snprintf (record->username, sizeof (record->username), "%s", username);
  }
  if (ip != NULL) {
    snprintf (record->last_ip, sizeof (record->last_ip), "%s", ip);
  }
  record->alpha.active = 0U;
  record->alpha.stage = 0U;
  record->alpha.eva_ready = 0U;
  record->alpha.awaiting_flag = 0U;
  record->alpha.velocity_fraction_c = 0.0;
  record->alpha.distance_travelled_ly = 0.0;
  record->alpha.distance_remaining_ly = 4.24;
  record->alpha.fuel_percent = 100.0;
  record->alpha.oxygen_days = 730.0;
  record->alpha.mission_time_years = 0.0;
  record->alpha.radiation_msv = 0.0;
  record->mailbox_count = 0U;
  record->flag_count = 0U;
  record->flag_history_count = 0U;
  record->last_updated = (uint64_t)time (NULL);
  memset (record->reserved, 0, sizeof (record->reserved));
  return true;
}

bool
user_data_load (const char *root, const char *username, const char *ip,
                user_data_record_t *record)
{
  if (record == NULL) {
    return false;
  }

  char path[PATH_MAX];
  if (!user_data_path_for (root, username, ip, false, path, sizeof (path))) {
    return false;
  }

  user_data_record_t temp;
  bool needs_upgrade = false;
  if (!user_data_load_raw (path, &temp, &needs_upgrade)) {
    return false;
  }

  user_data_normalize_record (&temp, username);
  user_data_profile_picture_overlay (root, username, &temp);
  if (needs_upgrade) {
    temp.version = USER_DATA_VERSION;
  }
  if (ip != NULL && ip[0] != '\0') {
    snprintf (temp.last_ip, sizeof (temp.last_ip), "%s", ip);
  }
  *record = temp;
  return true;
}

bool
user_data_save (const char *root, const user_data_record_t *record,
                const char *ip)
{
  if (record == NULL) {
    return false;
  }

  char path[PATH_MAX];
  const char *effective_ip
      = (ip != NULL && ip[0] != '\0') ? ip : record->last_ip;
  if (!user_data_path_for (root, record->username, effective_ip, true, path,
                           sizeof (path))) {
    return false;
  }

  if (!user_data_ensure_root (root)) {
    return false;
  }

  if (!user_data_ensure_parent (path)) {
    return false;
  }

  char temp_path[PATH_MAX];
  int written = snprintf (temp_path, sizeof (temp_path), "%s.tmp", path);
  if (written < 0 || (size_t)written >= sizeof (temp_path)) {
    return false;
  }

  FILE *fp = fopen (temp_path, "wb");
  if (fp == NULL) {
    return false;
  }

  user_data_record_t normalized = *record;
  user_data_normalize_record (&normalized, record->username);
  normalized.magic = USER_DATA_MAGIC;
  normalized.version = USER_DATA_VERSION;
  if (effective_ip != NULL && effective_ip[0] != '\0') {
    snprintf (normalized.last_ip, sizeof (normalized.last_ip), "%s",
              effective_ip);
  }

  user_data_record_t disk_record = normalized;
  /* Profile pictures are persisted in dedicated per-user .dat files. */
  memset (disk_record.profile_picture, 0, sizeof (disk_record.profile_picture));

  bool success = fwrite (&disk_record, sizeof (disk_record), 1U, fp) == 1U;
  int error = success ? 0 : errno;
  if (success && fflush (fp) != 0) {
    success = false;
    error = errno;
  }

  if (success) {
    int fd = fileno (fp);
    if (fd >= 0 && fsync (fd) != 0) {
      success = false;
      error = errno;
    }
  }

  if (fclose (fp) != 0) {
    if (success) {
      error = errno;
    }
    success = false;
  }

  if (!success) {
    unlink (temp_path);
    errno = error;
    return false;
  }

  if (rename (temp_path, path) != 0) {
    int rename_error = errno;
    unlink (temp_path);
    errno = rename_error;
    return false;
  }

  if (!user_data_profile_picture_store (root, &normalized)) {
    return false;
  }

  return true;
}

bool
user_data_ensure_exists (const char *root, const char *username, const char *ip,
                         user_data_record_t *record)
{
  if (record != NULL && user_data_load (root, username, ip, record)) {
    return true;
  }

  user_data_record_t temp;
  if (!user_data_init (&temp, username, ip)) {
    return false;
  }

  if (!user_data_save (root, &temp, ip)) {
    return false;
  }

  if (record != NULL) {
    *record = temp;
  }
  return true;
}

void
user_data_set_ssh_chat_server_config (user_data_record_t *record,
                                      const char *url, uint16_t port)
{
  if (record == NULL) {
    return;
  }
  if (url != NULL) {
    strncpy (record->ssh_chat_server_url, url,
             sizeof (record->ssh_chat_server_url) - 1);
    record->ssh_chat_server_url[sizeof (record->ssh_chat_server_url) - 1]
        = '\0';
  } else {
    record->ssh_chat_server_url[0] = '\0';
  }
  record->ssh_chat_server_port = port;
}

void
user_data_get_ssh_chat_server_config (const user_data_record_t *record,
                                      char *url, size_t url_len, uint16_t *port)
{
  if (record == NULL) {
    if (url != NULL && url_len > 0) {
      url[0] = '\0';
    }
    if (port != NULL) {
      *port = 0;
    }
    return;
  }

  if (url != NULL && url_len > 0) {
    strncpy (url, record->ssh_chat_server_url, url_len - 1);
    url[url_len - 1] = '\0';
  }
  if (port != NULL) {
    *port = record->ssh_chat_server_port;
  }
}
