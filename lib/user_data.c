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
#define USER_DATA_VERSION 1U

static bool user_data_is_directory(const char *path) {
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  struct stat st;
  if (stat(path, &st) != 0) {
    return false;
  }

  return S_ISDIR(st.st_mode);
}

static bool user_data_create_directory(const char *path) {
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  if (user_data_is_directory(path)) {
    return true;
  }

  if (mkdir(path, 0750) == 0) {
    return true;
  }

  if (errno == EEXIST) {
    return user_data_is_directory(path);
  }

  return false;
}

static bool user_data_ensure_parent(const char *path) {
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  char temp[PATH_MAX];
  snprintf(temp, sizeof(temp), "%s", path);
  char *parent = dirname(temp);
  if (parent == NULL || parent[0] == '\0') {
    return false;
  }

  return user_data_create_directory(parent);
}

bool user_data_ensure_root(const char *root) {
  if (root == NULL || root[0] == '\0') {
    return false;
  }

  return user_data_create_directory(root);
}

bool user_data_sanitize_username(const char *username, char *sanitized, size_t length) {
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
    if (isalnum(ch)) {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = (char)tolower(ch);
      }
    } else if (ch == '-' || ch == '_' || ch == '.') {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = (char)ch;
      }
    } else if (!isspace(ch)) {
      if (out_idx + 1U < length) {
        sanitized[out_idx++] = '_';
      }
    }
  }

  if (out_idx == 0U) {
    if (length < 5U) {
      return false;
    }
    snprintf(sanitized, length, "user");
    return true;
  }

  sanitized[out_idx] = '\0';
  return true;
}

bool user_data_path_for(const char *root, const char *username, char *path, size_t length) {
  if (path == NULL || length == 0U || root == NULL || root[0] == '\0') {
    return false;
  }

  char sanitized[SSH_CHATTER_USERNAME_LEN * 2U];
  if (!user_data_sanitize_username(username, sanitized, sizeof(sanitized))) {
    return false;
  }

  int written = snprintf(path, length, "%s/%s.dat", root, sanitized);
  if (written < 0 || (size_t)written >= length) {
    return false;
  }
  return true;
}

static void user_data_normalize_record(user_data_record_t *record, const char *username) {
  if (record == NULL) {
    return;
  }

  if (record->mailbox_count > USER_DATA_MAILBOX_LIMIT) {
    record->mailbox_count = USER_DATA_MAILBOX_LIMIT;
  }
  if (record->flag_history_count > USER_DATA_FLAG_HISTORY_LIMIT) {
    record->flag_history_count = USER_DATA_FLAG_HISTORY_LIMIT;
  }
  if (username != NULL && username[0] != '\0') {
    snprintf(record->username, sizeof(record->username), "%s", username);
  }
}

bool user_data_init(user_data_record_t *record, const char *username) {
  if (record == NULL) {
    return false;
  }

  memset(record, 0, sizeof(*record));
  record->magic = USER_DATA_MAGIC;
  record->version = USER_DATA_VERSION;
  if (username != NULL) {
    snprintf(record->username, sizeof(record->username), "%s", username);
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
  record->last_updated = (uint64_t)time(NULL);
  memset(record->reserved, 0, sizeof(record->reserved));
  return true;
}

bool user_data_load(const char *root, const char *username, user_data_record_t *record) {
  if (record == NULL) {
    return false;
  }

  char path[PATH_MAX];
  if (!user_data_path_for(root, username, path, sizeof(path))) {
    return false;
  }

  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    return false;
  }

  user_data_record_t temp;
  size_t read = fread(&temp, sizeof(temp), 1U, fp);
  fclose(fp);
  if (read != 1U) {
    return false;
  }

  if (temp.magic != USER_DATA_MAGIC || temp.version != USER_DATA_VERSION) {
    return false;
  }

  user_data_normalize_record(&temp, username);
  *record = temp;
  return true;
}

bool user_data_save(const char *root, const user_data_record_t *record) {
  if (record == NULL) {
    return false;
  }

  char path[PATH_MAX];
  if (!user_data_path_for(root, record->username, path, sizeof(path))) {
    return false;
  }

  if (!user_data_ensure_root(root)) {
    return false;
  }

  if (!user_data_ensure_parent(path)) {
    return false;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    return false;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    return false;
  }

  user_data_record_t copy = *record;
  user_data_normalize_record(&copy, record->username);
  copy.magic = USER_DATA_MAGIC;
  copy.version = USER_DATA_VERSION;

  bool success = fwrite(&copy, sizeof(copy), 1U, fp) == 1U;
  int error = success ? 0 : errno;
  if (success && fflush(fp) != 0) {
    success = false;
    error = errno;
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      error = errno;
    }
  }

  if (fclose(fp) != 0) {
    if (success) {
      error = errno;
    }
    success = false;
  }

  if (!success) {
    unlink(temp_path);
    errno = error;
    return false;
  }

  if (rename(temp_path, path) != 0) {
    int rename_error = errno;
    unlink(temp_path);
    errno = rename_error;
    return false;
  }

  return true;
}

bool user_data_ensure_exists(const char *root, const char *username, user_data_record_t *record) {
  if (record != NULL && user_data_load(root, username, record)) {
    return true;
  }

  user_data_record_t temp;
  if (!user_data_init(&temp, username)) {
    return false;
  }

  if (!user_data_save(root, &temp)) {
    return false;
  }

  if (record != NULL) {
    *record = temp;
  }
  return true;
}
